// Embeds the application manifest: themed (v6) common controls, per-monitor DPI awareness
// and UTF-8. Elevation is requested at run time instead of via the manifest so the CLI can
// explain itself before the UAC prompt appears.
//
// Also embeds the icon and a version resource (product, description, version, source URL). An exe
// that says what it is looks less anonymous to people and to antivirus heuristics alike.
fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest::embed_manifest(embed_manifest::new_manifest("WTFIsStalling")).expect("unable to embed manifest");

        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico")
            .set("ProductName", "WTFIsStalling")
            .set("FileDescription", "WTFIsStalling - finds what is stalling this PC")
            .set("CompanyName", "Tyberious and the WTFIsStalling contributors")
            .set("LegalCopyright", "MIT License. Source: https://github.com/Tyberious/WTFIsStalling")
            .set("Comments", "Open source: https://github.com/Tyberious/WTFIsStalling");
        res.compile().expect("unable to embed icon and version resource");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icon.ico");
}
