//! RDP Gate Server: the window for managing the server on this PC (computers,
//! 6-digit codes, the beacon, the network, updates), so nothing needs the
//! command line. It changes the same files as `rdpgate-server` and asks the
//! RDPGate service to restart when a setting needs it.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod ui;

#[cfg(windows)]
fn main() {
    ui::main();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The RDP Gate Server window is only for Windows.");
}
