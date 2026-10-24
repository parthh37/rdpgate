//! Makes sure the data folder (TOTP secret, identity key, GitHub token) is
//! readable by SYSTEM and Administrators only, whoever created it.
//!
//! On Windows any user can create folders in C:\ProgramData. A folder made in
//! advance by an ordinary user would stay theirs (and so would its ACL), so
//! ownership is taken back and every ACL entry is replaced. A folder that is
//! a junction or symlink is refused outright: writes as SYSTEM through it
//! could land anywhere.

use std::path::Path;

#[cfg(windows)]
pub fn harden(dir: &Path) -> Result<(), String> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::process::CommandExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let is_link = |p: &Path| {
        std::fs::symlink_metadata(p).map(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0).unwrap_or(false)
    };
    if is_link(dir) {
        return Err(format!("{} is a junction or symlink; refusing to use it", dir.display()));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if is_link(&e.path()) {
                return Err(format!("{} is a junction or symlink; remove it", e.path().display()));
            }
        }
    }
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let icacls = format!(r"{root}\System32\icacls.exe");
    let d = dir.as_os_str();
    // The last step is for the folder alone: its files then inherit the two
    // grants. With /T it would strip each file's inherited entries and add
    // (OI)(CI) grants that a file ignores, leaving every file with an empty
    // ACL that nobody, Administrators included, may read.
    let steps: [&[&str]; 3] = [
        &["/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"],
        &["/reset", "/T", "/C", "/Q"],
        &["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/C", "/Q"],
    ];
    for args in steps {
        let out = std::process::Command::new(&icacls)
            .arg(d)
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("icacls: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "could not secure {} (run as Administrator): {}",
                dir.display(),
                String::from_utf8_lossy(&out.stdout).trim()
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
pub fn harden(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if std::fs::symlink_metadata(dir).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        return Err(format!("{} is a symlink; refusing to use it", dir.display()));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| format!("{}: {e}", dir.display()))
}
