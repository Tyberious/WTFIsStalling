//! File names for disk I/O: NT device path -> drive letter, the privacy rule that decides how
//! much of a path a public report may show, and plain words for files nobody recognizes.
//!
//! PRIVACY. Reports get pasted into forums and issue trackers. A file path carries the person's
//! Windows user name and the names of their folders and documents, none of which helps anyone
//! diagnose a stall. So `public_path` is the single gate every path passes through before it is
//! printed or stored, and it shows a full path only where the path cannot be personal:
//!   * files sitting straight on a volume root (pagefile.sys, $Mft, hiberfil.sys),
//!   * well-known system files wherever they are,
//!   * everything under Windows, Program Files, ProgramData and the usual game libraries.
//!
//! Anything under `\Users\` loses the user name and every folder: `C:\Users\...\game.log`.
//! Anything else keeps only its drive and file name: `D:\...\holiday.mp4`. Knowing *which*
//! file waited is the point of the feature; knowing whose it is never is.

use std::collections::HashMap;

/// Longest path the report will print. Beyond it the middle is dropped.
const MAX_SHOWN: usize = 64;

/// Folders whose contents are the same on every Windows PC (or are a game library, which is
/// public by nature), so a full path gives nothing away. Matched case-insensitively against the
/// first folder of the path.
const PUBLIC_ROOTS: &[&str] = &[
    "Windows",
    "Windows.old",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "$Extend",
    "$Recycle.Bin",
    "SteamLibrary",
    "Steam",
    "Games",
    "Epic Games",
    "GOG Games",
    "GOG Galaxy",
    "XboxGames",
    "Battle.net",
    "Riot Games",
    "Origin Games",
    "EA Games",
    "Ubisoft",
];

/// `\Device\HarddiskVolume3` -> `C:`, built from the drive letters this PC has.
#[derive(Default, Clone)]
pub struct DosMap {
    /// (NT device path without trailing backslash, "C:"), longest device first so that a
    /// longer device name never loses to a shorter one that happens to be its prefix.
    devices: Vec<(String, String)>,
}

impl DosMap {
    pub fn from_pairs(pairs: &[(&str, &str)]) -> DosMap {
        let mut devices: Vec<(String, String)> = pairs.iter().map(|(d, l)| ((*d).to_string(), (*l).to_string())).collect();
        devices.sort_by_key(|(d, _)| std::cmp::Reverse(d.len()));
        DosMap { devices }
    }

    /// Asks Windows what each drive letter is a junction to.
    ///
    /// GetLogicalDriveStringsW fills the buffer with null-terminated strings ("C:\", "D:\"...)
    /// followed by an extra null and returns the length in characters, or the required length
    /// when the buffer is too small. QueryDosDeviceW takes the name *without* a trailing
    /// backslash ("use \"C:\", not \"C:\\\"") and stores "the current mapping for the device"
    /// as the first of one or more null-terminated strings; later strings are prior mappings,
    /// which we ignore. It returns 0 on failure.
    /// Sources: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-querydosdevicew
    ///          https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getlogicaldrivestringsw
    pub fn live() -> DosMap {
        use windows_sys::Win32::Storage::FileSystem::{GetLogicalDriveStringsW, QueryDosDeviceW};
        let mut pairs: Vec<(String, String)> = Vec::new();
        unsafe {
            let mut drives = [0u16; 512];
            let n = GetLogicalDriveStringsW(drives.len() as u32, drives.as_mut_ptr()) as usize;
            for root in drives[..n.min(drives.len())].split(|c| *c == 0).filter(|s| s.len() >= 2) {
                let letter = String::from_utf16_lossy(&root[..2]); // "C:" out of "C:\"
                let mut target = [0u16; 1024];
                let name: Vec<u16> = root[..2].iter().copied().chain(std::iter::once(0)).collect();
                let got = QueryDosDeviceW(name.as_ptr(), target.as_mut_ptr(), target.len() as u32) as usize;
                if got == 0 {
                    continue;
                }
                let first = target[..got.min(target.len())].split(|c| *c == 0).next().unwrap_or(&[]);
                if !first.is_empty() {
                    pairs.push((String::from_utf16_lossy(first), letter));
                }
            }
        }
        let mut map = DosMap { devices: pairs };
        map.devices.sort_by_key(|(d, _)| std::cmp::Reverse(d.len()));
        map
    }

    /// `\Device\HarddiskVolume3\Windows\x.dll` -> `C:\Windows\x.dll`. Anything that does not
    /// start with a known device is returned unchanged: an unknown device path still names the
    /// file, which is most of the value.
    pub fn to_dos(&self, path: &str) -> String {
        for (device, letter) in &self.devices {
            if path.len() > device.len() && path.as_bytes()[device.len()] == b'\\' && path[..device.len()].eq_ignore_ascii_case(device) {
                return format!("{letter}{}", &path[device.len()..]);
            }
        }
        path.to_string()
    }
}

/// The file name at the end of a path, whatever kind of path it is.
pub fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Splits `C:` or `\Device\HarddiskVolume3` off the front. Returns ("", path) for anything else,
/// including the drive-letter-less paths that FileIo_Name is documented to carry
/// ("Full path to the file, not including the drive letter").
fn split_prefix(path: &str) -> (&str, &str) {
    let b = path.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        return path.split_at(2);
    }
    if path.len() > 8 && path[..8].eq_ignore_ascii_case("\\Device\\") {
        if let Some(at) = path[8..].find('\\') {
            return path.split_at(8 + at);
        }
    }
    ("", path)
}

/// Drops the middle of a path too long for the report, always keeping the file name.
fn shorten(prefix: &str, dirs: &[&str], file: &str) -> String {
    if prefix.is_empty() && dirs.is_empty() {
        return file.to_string(); // a bare name, with nothing to anchor it to
    }
    let joined = |dirs: &[&str]| {
        let mut s = String::from(prefix);
        for d in dirs {
            s.push('\\');
            s.push_str(d);
        }
        s.push('\\');
        s.push_str(file);
        s
    };
    let full = joined(dirs);
    if full.chars().count() <= MAX_SHOWN {
        return full;
    }
    for keep in (1..dirs.len().min(2) + 1).rev() {
        let mut short = vec!["..."];
        short.extend_from_slice(&dirs[dirs.len() - keep..]);
        let candidate = joined(&short);
        if candidate.chars().count() <= MAX_SHOWN {
            return candidate;
        }
    }
    let bare = joined(&["..."]);
    if bare.chars().count() <= MAX_SHOWN {
        bare
    } else {
        // A pathological file name. Keep both ends: the extension is often the useful half.
        let chars: Vec<char> = file.chars().collect();
        let head: String = chars[..MAX_SHOWN / 2].iter().collect();
        let tail: String = chars[chars.len() - MAX_SHOWN / 3..].iter().collect();
        format!("{head}...{tail}")
    }
}

/// The only way a file path may reach the report. See the privacy note at the top of this file.
pub fn public_path(path: &str) -> String {
    // Everything below reasons about backslash-separated components. A path written with forward
    // slashes would otherwise arrive as ONE component, be taken for a file in a volume root, and be
    // printed whole: user name, folders and all.
    let normalized = path.trim_end_matches('\0').trim().replace('/', "\\");
    let path = normalized.as_str();
    if path.is_empty() {
        return String::new();
    }
    // A network path names someone's server and share; neither helps and both identify.
    if path.starts_with("\\\\") {
        let file = base_name(path);
        return if file.is_empty() { String::new() } else { shorten("\\\\...", &[], &personal_name(file, false)) };
    }
    let (prefix, rest) = split_prefix(path);
    let comps: Vec<&str> = rest.split('\\').filter(|c| !c.is_empty()).collect();
    if comps.is_empty() {
        return String::new();
    }
    let dirs = &comps[..comps.len() - 1];
    let file = comps[comps.len() - 1];
    if dirs.iter().any(|c| c.eq_ignore_ascii_case("Users")) {
        // Never the user name, never their folder names, whatever else is in the path. The file
        // name survives only when it is a program's data (AppData, or a program / game file
        // type): "TaxReturn_JohnSmith.pdf" says as much as the folder it sat in.
        let program_data = dirs.iter().any(|c| c.eq_ignore_ascii_case("AppData"));
        return shorten(prefix, &["Users", "..."], &personal_name(file, program_data));
    }
    // Folders whose names start with '$' belong to Windows ($Extend, $Recycle.Bin, $WinREAgent),
    // but only the '$' part of the path is Windows' own: the Recycle Bin keeps one folder per
    // account named by its security ID (S-1-5-21-...), which identifies the account, and a deleted
    // folder keeps its original name and contents inside it. So the '$' components are shown and
    // everything after them is treated like a personal folder.
    let dollar = dirs.iter().take_while(|c| c.starts_with('$')).count();
    if dollar > 0 {
        return if dollar == dirs.len() {
            shorten(prefix, dirs, file)
        } else {
            let mut shown: Vec<&str> = dirs[..dollar].to_vec();
            shown.push("...");
            // "$R4F2KQ1.pdf" is a name Windows made up; anything else is the person's.
            let name = if file.starts_with('$') { file.to_string() } else { personal_name(file, false) };
            shorten(prefix, &shown, &name)
        };
    }
    // A system file NAME ($Mft, pagefile.sys) is only public where Windows keeps it, at the root:
    // "D:\Clients\Smith\$notes.txt" must not print its folders because the name starts with '$'.
    let public = dirs.is_empty() || PUBLIC_ROOTS.iter().any(|r| r.eq_ignore_ascii_case(dirs[0]));
    if public {
        shorten(prefix, dirs, file)
    } else {
        // Somebody's own folder on a data drive: same caution as a user profile.
        shorten(prefix, &["..."], &personal_name(file, false))
    }
}

/// File types whose NAMES describe a program, not a person, wherever they sit: safe to show from
/// a personal folder, and the ones worth showing ("the game's .pak on the hard drive"). Kept short
/// on purpose. Data formats (.xml, .json, .db, .log, .dat, .ini, .iso, .vhd) and partial downloads
/// are not here: "Medical records.xml" and the title of what someone is downloading are personal,
/// whatever the extension. Under AppData every name is shown anyway; that is program data.
const PROGRAM_EXTS: &[&str] = &["exe", "dll", "sys", "msi", "cab", "pdb", "etl"];

/// What to show for a file in a personal location: its name when that names a program's data,
/// otherwise only what kind of file it was.
fn personal_name(file: &str, program_data: bool) -> String {
    // "notes.txt:password" is an alternate data stream: the part after the colon is free text.
    let file = file.split(':').next().unwrap_or(file);
    // Letters and digits only, so nothing but a file type can ride along in the placeholder.
    let ext =
        file.rsplit_once('.').map(|(_, e)| e).filter(|e| !e.is_empty() && e.len() <= 8 && e.chars().all(|c| c.is_ascii_alphanumeric()));
    let program_type = ext.is_some_and(|e| PROGRAM_EXTS.iter().any(|p| p.eq_ignore_ascii_case(e))) || is_game_asset(file);
    if program_data || program_type {
        return file.to_string();
    }
    match ext {
        Some(e) => format!("(a .{} file)", e.to_lowercase()),
        None => "(a file)".to_string(),
    }
}

/// Files that are the same on every Windows PC, so their full path gives nothing away.
pub fn system_file(file: &str) -> bool {
    let f = file.to_ascii_lowercase();
    f.starts_with('$')
        || matches!(
            f.as_str(),
            "pagefile.sys" | "swapfile.sys" | "hiberfil.sys" | "ntuser.dat" | "usrclass.dat" | "bootmgr" | "bootstat.dat"
        )
}

/// Game asset containers: a slow read of one of these is a game loading its data.
const GAME_ASSET_EXTS: &[&str] = &[
    "pak", "pck", "bundle", "uasset", "umap", "ucas", "utoc", "vpk", "wad", "bsa", "ba2", "rpf", "sga", "big", "arc", "cas", "toc", "xnb",
    "assets", "resource", "forge", "psarc", "vpp", "dds",
];

pub fn is_game_asset(path: &str) -> bool {
    match base_name(path).rsplit_once('.') {
        Some((_, ext)) => GAME_ASSET_EXTS.iter().any(|e| ext.eq_ignore_ascii_case(e)),
        None => false,
    }
}

/// Is this Windows' paging file? A slow one means something different from every other file:
/// the PC ran short of memory rather than a program asking for its own data.
pub fn is_paging_file(path: &str) -> bool {
    let f = base_name(path).to_ascii_lowercase();
    f == "pagefile.sys" || f == "swapfile.sys"
}

/// Plain words for a file a non-technical reader has never heard of. `None` means the file name
/// speaks for itself (or nothing useful can be said), and the report then just prints the name.
pub fn explain(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let file = base_name(&lower).to_string();
    let ext = file.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    if file == "pagefile.sys" || file == "swapfile.sys" {
        return Some(
            "Windows' paging file: the PC was short of memory and pushed programs out to this disk, so every program that needs \
             that memory back has to wait for the drive",
        );
    }
    if file == "hiberfil.sys" {
        return Some("the file Windows writes when it hibernates or shuts down with Fast Startup on");
    }
    if file.starts_with('$') {
        return Some("the file system's own bookkeeping, not anyone's data: something was creating, listing or deleting a lot of files");
    }
    if file == "ntuser.dat" || file == "usrclass.dat" || matches!(file.as_str(), "software" | "system" | "sam" | "security" | "default") {
        return Some("part of the Windows registry, where settings live");
    }
    if ext == "etl" {
        return Some("a tracing log written by a profiler or logging tool (not this one: it keeps nothing on disk)");
    }
    if lower.contains("\\cache") || lower.contains("cache_data") || lower.contains("\\code cache") {
        return Some("a web browser's cache");
    }
    if ext == "vdm" || file.starts_with("mpenginedb") {
        return Some("Microsoft Defender's virus definitions");
    }
    if ext == "vhd" || ext == "vhdx" {
        return Some("a virtual disk, used by virtual machines, WSL and some games' installers");
    }
    if is_game_asset(&lower) {
        return Some("a game's data file: the game was loading assets from this drive");
    }
    if ext == "dll" || ext == "exe" || ext == "sys" {
        return Some("program code being loaded from disk");
    }
    None
}

/// Files ranked by how long requests to them waited, biggest total wait first.
/// `entries` is (display name, disk, requests, total wait, worst wait); names that are equal
/// are merged, which is what makes several handles to one file read as one row.
pub fn rank(entries: &[(String, u32, u64, i64, i64)], top: usize) -> Vec<(String, u32, u64, i64, i64)> {
    let mut by_name: HashMap<(String, u32), (u64, i64, i64)> = HashMap::new();
    for (name, disk, count, total, max) in entries {
        let e = by_name.entry((name.clone(), *disk)).or_default();
        e.0 += count;
        e.1 += total;
        e.2 = e.2.max(*max);
    }
    let mut v: Vec<(String, u32, u64, i64, i64)> = by_name.into_iter().map(|((name, disk), (c, t, m))| (name, disk, c, t, m)).collect();
    // Total wait decides; name breaks ties so two runs on the same data rank identically.
    v.sort_by(|a, b| b.3.cmp(&a.3).then_with(|| a.0.cmp(&b.0)));
    v.truncate(top);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recycle_bin_and_dollar_names_do_not_leak_the_account_or_folders() {
        let sid = r"\Device\HarddiskVolume3\$Recycle.Bin\S-1-5-21-1004336348-1177238915-682003330-1001\$RX2Q9ZA.pdf";
        let shown = public_path(sid);
        assert!(!shown.contains("S-1-5"), "the account's security ID: {shown}");
        assert_eq!(shown, r"\Device\HarddiskVolume3\$Recycle.Bin\...\$RX2Q9ZA.pdf");
        // A deleted folder keeps its own name and contents inside the bin.
        let inner = public_path(r"D:\$Recycle.Bin\S-1-5-21-1-2-3-1001\$R8K1\Divorce papers\draft.docx");
        assert!(!inner.contains("Divorce") && !inner.contains("draft"), "{inner}");
        // Windows' own '$' folders stay readable.
        assert_eq!(public_path(r"C:\$Extend\$UsnJrnl"), r"C:\$Extend\$UsnJrnl");
        // A name starting with '$' in someone's own folder does not make the folders public.
        let own = public_path(r"D:\Clients\Smith\$notes.txt");
        assert!(!own.contains("Clients") && !own.contains("Smith"), "{own}");
        assert_eq!(public_path(r"C:\$Mft"), r"C:\$Mft");
    }

    #[test]
    fn the_holes_a_review_found_stay_closed() {
        // Forward slashes used to arrive as one component and be printed whole.
        let shown = public_path("C:/Users/Jane/Documents/secret.pdf");
        assert_eq!(shown, r"C:\Users\...\(a .pdf file)");
        assert!(!public_path(r"\Device\HarddiskVolume3/Users/Jane/x.docx").to_lowercase().contains("jane"));
        // Data formats are personal too, whatever the extension.
        for name in ["Medical records.xml", "passwords.db", "chat.log", "budget.json", "diary.dat", "backup.iso"] {
            let shown = public_path(&format!(r"C:\Users\Jane\Documents\{name}"));
            assert!(shown.starts_with(r"C:\Users\...\(a .") && !shown.contains(&name[..4]), "{name} -> {shown}");
        }
        // Text after an alternate-data-stream colon must not ride along in the placeholder.
        assert_eq!(public_path(r"D:\Personal\notes.txt:JaneDoePassword"), r"D:\...\(a .txt file)");
        assert_eq!(public_path(r"D:\Personal\odd.na me"), r"D:\...\(a file)");
    }

    #[test]
    fn personal_file_names_are_not_shown_unless_they_name_program_data() {
        // The name of a personal document says as much as its folder.
        assert_eq!(public_path(r"C:\Users\Jane Doe\Documents\Taxes\TaxReturn_JaneDoe.pdf"), r"C:\Users\...\(a .pdf file)");
        assert_eq!(public_path(r"D:\Private\Videos\holiday 2026.MP4"), r"D:\...\(a .mp4 file)");
        assert_eq!(public_path(r"D:\Stuff\notes"), r"D:\...\(a file)");
        // Program data is what the report is for, and names no one.
        assert_eq!(public_path(r"C:\Users\Jane Doe\AppData\Local\Game\Saved\shadercache.bin"), r"C:\Users\...\shadercache.bin");
        assert_eq!(public_path(r"C:\Users\Jane Doe\AppData\Roaming\App\profile.xyz"), r"C:\Users\...\profile.xyz");
        // What someone is downloading is theirs to keep quiet about.
        assert_eq!(public_path(r"E:\Downloads\Some.Film.2026.mkv.!qB"), r"E:\...\(a file)");
        assert_eq!(public_path(r"E:\Downloads\setup.exe"), r"E:\...\setup.exe");
        assert_eq!(public_path(r"E:\MyGames\Thing\data.pak"), r"E:\...\data.pak");
        for shown in [public_path(r"C:\Users\Jane Doe\Desktop\x.docx"), public_path(r"C:\users\JANE DOE\x.docx")] {
            assert!(!shown.to_lowercase().contains("jane"), "{shown}");
        }
    }

    fn map() -> DosMap {
        DosMap::from_pairs(&[("\\Device\\HarddiskVolume3", "C:"), ("\\Device\\HarddiskVolume11", "D:")])
    }

    #[test]
    fn nt_device_paths_become_drive_letters() {
        let m = map();
        assert_eq!(m.to_dos("\\Device\\HarddiskVolume3\\Windows\\x.dll"), "C:\\Windows\\x.dll");
        // Volume11 must not be matched by the Volume1... prefix of a shorter device.
        assert_eq!(m.to_dos("\\Device\\HarddiskVolume11\\game.pak"), "D:\\game.pak");
        // Devices are case-insensitive like the rest of the Windows file namespace.
        assert_eq!(m.to_dos("\\device\\harddiskvolume3\\a.txt"), "C:\\a.txt");
        // Not a volume we know: unchanged rather than mangled.
        assert_eq!(m.to_dos("\\Device\\Mup\\server\\share\\a.txt"), "\\Device\\Mup\\server\\share\\a.txt");
        assert_eq!(m.to_dos("\\Device\\HarddiskVolume3"), "\\Device\\HarddiskVolume3", "no file part to keep");
        assert_eq!(DosMap::default().to_dos("\\Device\\HarddiskVolume3\\a"), "\\Device\\HarddiskVolume3\\a");
    }

    #[test]
    fn the_user_name_never_reaches_the_report() {
        for path in [
            "C:\\Users\\Jennifer\\Documents\\Taxes 2025\\return.xlsx",
            "C:\\users\\jennifer\\AppData\\Local\\Temp\\x.tmp",
            "C:\\Users\\Jennifer\\NTUSER.DAT",
            "\\Device\\HarddiskVolume3\\Users\\Jennifer\\Desktop\\resume.docx",
        ] {
            let shown = public_path(path);
            let lower = shown.to_ascii_lowercase();
            assert!(!lower.contains("jennifer"), "{path} -> {shown}");
            assert!(!lower.contains("taxes"), "{path} -> {shown}");
            assert!(!lower.contains("documents"), "folder names under Users are private too: {shown}");
        }
        assert_eq!(public_path("C:\\Users\\Jennifer\\Desktop\\resume.docx"), "C:\\Users\\...\\(a .docx file)");
    }

    #[test]
    fn system_and_game_paths_are_shown_in_full() {
        assert_eq!(public_path("C:\\pagefile.sys"), "C:\\pagefile.sys");
        assert_eq!(public_path("\\Device\\HarddiskVolume3\\$Mft"), "\\Device\\HarddiskVolume3\\$Mft");
        assert_eq!(public_path("C:\\Windows\\System32\\config\\SOFTWARE"), "C:\\Windows\\System32\\config\\SOFTWARE");
        assert_eq!(
            public_path("D:\\SteamLibrary\\steamapps\\common\\Game\\game.pak"),
            "D:\\SteamLibrary\\steamapps\\common\\Game\\game.pak"
        );
        // Odd casing must not turn a public folder into a private one.
        assert_eq!(public_path("c:\\PROGRAM FILES\\App\\app.exe"), "c:\\PROGRAM FILES\\App\\app.exe");
    }

    #[test]
    fn private_and_network_paths_keep_at_most_the_kind_of_file() {
        assert_eq!(public_path("D:\\Backups\\Divorce\\papers.pdf"), "D:\\...\\(a .pdf file)");
        assert_eq!(public_path("\\\\NAS-JENNIFER\\family\\photos\\2019.jpg"), "\\\\...\\(a .jpg file)");
        // A path with no directory at all, and one with nothing but a name.
        assert_eq!(public_path("notes.txt"), "notes.txt");
        // FileIo_Name is documented to carry the path without a drive letter; still redacted.
        assert_eq!(public_path("\\Users\\Jennifer\\Desktop\\resume.docx"), "\\Users\\...\\(a .docx file)");
        assert_eq!(public_path(""), "");
        assert_eq!(public_path("\\\\"), "");
    }

    #[test]
    fn very_long_paths_are_shortened_but_always_keep_the_file_name() {
        let deep = format!("C:\\Program Files\\{}\\payload.bin", ["averylongfoldername"; 10].join("\\"));
        let shown = public_path(&deep);
        assert!(shown.chars().count() <= MAX_SHOWN, "{shown}");
        assert!(shown.ends_with("payload.bin"), "{shown}");
        assert!(shown.starts_with("C:\\"), "{shown}");

        let silly = format!("C:\\Windows\\{}.log", "z".repeat(300));
        let shown = public_path(&silly);
        assert!(shown.chars().count() <= MAX_SHOWN, "{} chars: {shown}", shown.chars().count());
        assert!(shown.ends_with(".log"), "the extension survives: {shown}");
    }

    #[test]
    fn well_known_files_are_explained_in_plain_words() {
        assert!(explain("C:\\pagefile.sys").unwrap().contains("short of memory"));
        assert!(explain("\\Device\\HarddiskVolume3\\$LogFile").unwrap().contains("bookkeeping"));
        assert!(explain("D:\\Games\\x\\data.pak").unwrap().contains("game"));
        assert!(explain("C:\\temp\\trace.ETL").unwrap().contains("profiler"));
        assert!(explain("C:\\Windows\\System32\\ntdll.dll").unwrap().contains("program code"));
        assert!(explain("D:\\...\\holiday.mp4").is_none(), "an ordinary file speaks for itself");
        assert!(is_paging_file("C:\\pagefile.sys") && !is_paging_file("C:\\Windows\\x.dll"));
        assert!(is_game_asset("x.UASSET") && !is_game_asset("x.txt") && !is_game_asset("noextension"));
    }

    #[test]
    fn files_are_ranked_by_total_wait_and_merged_by_name() {
        let entries = vec![
            ("C:\\pagefile.sys".to_string(), 0u32, 3u64, 300i64, 200i64),
            ("C:\\pagefile.sys".to_string(), 0, 2, 100, 90),
            ("D:\\game.pak".to_string(), 1, 1, 500, 500),
            ("C:\\pagefile.sys".to_string(), 1, 1, 10, 10),
        ];
        let top = rank(&entries, 8);
        assert_eq!(top[0], ("D:\\game.pak".to_string(), 1, 1, 500, 500));
        assert_eq!(top[1], ("C:\\pagefile.sys".to_string(), 0, 5, 400, 200), "same file and disk merge");
        assert_eq!(top[2].1, 1, "the same name on another disk stays its own row");
        assert_eq!(rank(&entries, 1).len(), 1);
        assert!(rank(&[], 8).is_empty());
    }

    /// Not an assertion about this PC, just proof the live lookup works where it runs.
    #[test]
    fn live_drive_letters_can_be_read() {
        let m = DosMap::live();
        for (device, letter) in &m.devices {
            println!("{letter} = {device}");
            assert!(letter.ends_with(':'));
        }
        println!("{} drive letter(s) mapped", m.devices.len());
    }
}
