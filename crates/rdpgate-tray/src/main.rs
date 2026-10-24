//! RDP Gate tray icon: sits in the notification area of the server PC and
//! shows whether the RDPGate service is running, so you can tell at a glance.
//! Click it to open RDP Gate Server; right-click it for the service state
//! and to start the service. It starts when you sign in to Windows.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(any(windows, test))]
mod icon;
#[cfg(windows)]
mod tray;
#[cfg(any(windows, test))]
mod watch;

#[cfg(windows)]
fn main() {
    tray::main();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The RDP Gate tray icon is only for Windows.");
}
