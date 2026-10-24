fn main() {
    // Runs as the signed-in person (no Administrator prompt at every sign-in)
    // and aware of display scaling, so the icon is drawn at the taskbar's
    // real size instead of being stretched.
    #[cfg(windows)]
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        use embed_manifest::{embed_manifest, new_manifest};
        embed_manifest(new_manifest("RDPGate.Tray")).expect("embed the Windows manifest");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
