fn main() {
    // Windows asks for Administrator rights when the window opens: the
    // server's data folder is locked to Administrators and SYSTEM. Debug
    // builds skip it, to try the window on a test folder (--data).
    #[cfg(windows)]
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() && std::env::var("PROFILE").as_deref() == Ok("release") {
        use embed_manifest::{embed_manifest, manifest::ExecutionLevel, new_manifest};
        embed_manifest(new_manifest("RDPGate.Server").requested_execution_level(ExecutionLevel::RequireAdministrator))
            .expect("embed the Windows manifest");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
