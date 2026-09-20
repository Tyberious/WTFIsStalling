// Embeds the application manifest: themed (v6) common controls, per-monitor DPI awareness
// and UTF-8. Elevation is requested at run time instead of via the manifest so the CLI can
// explain itself before the UAC prompt appears.
fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest::embed_manifest(embed_manifest::new_manifest("WTFIsStalling")).expect("unable to embed manifest");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
