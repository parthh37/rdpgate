//! Turning protection on later instead of during Setup.
//!
//! Locking Windows Firewall down drops every Remote Desktop connection that
//! didn't come through RDP Gate, including the one Setup may be running
//! over, and at that point no computer is enrolled to sign back in. So Setup
//! can leave Remote Desktop as it was and mark protection as pending. The
//! service then locks down by itself once someone has signed in through RDP
//! Gate *and* has a live Remote Desktop connection from that address: the
//! whole path (router, beacon, codes, device, RDP port) is proven to work,
//! and that address's own grant keeps it connected through the change.

use crate::firewall::Firewall;
use crate::grants::Grant;
use crate::state::Store;

/// Whether protection can be turned on now without locking the owner out.
pub fn ready(grants: &[Grant]) -> bool {
    grants.iter().any(|g| g.last_connected.is_some())
}

/// Locks Remote Desktop behind RDP Gate and records that it's done. On
/// failure protection stays pending, so it is tried again later.
pub fn apply(fw: &dyn Firewall, store: &Store) -> Result<Vec<String>, String> {
    let disabled = fw.lock_down()?;
    store.update(|st| {
        st.protection_pending = false;
        Ok(())
    })?;
    Ok(disabled)
}

pub fn set_pending(store: &Store, pending: bool) -> Result<(), String> {
    store.update(|st| {
        st.protection_pending = pending;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::DryRun;
    use std::sync::atomic::Ordering;

    #[test]
    fn waits_for_a_connected_sign_in_then_locks_down() {
        let dir = std::env::temp_dir().join(format!("rdpgate-protect-{}", rdpgate_core::random_token::<6>()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::new(&dir);
        store.init("owner").unwrap();
        set_pending(&store, true).unwrap();

        let mut g = Grant {
            ip: "81.2.69.160".parse().unwrap(),
            who: "device mac".into(),
            created: 0,
            expires: 0,
            hard_expires: 0,
            last_connected: None,
            revoke_token: String::new(),
            link: None,
        };
        assert!(!ready(&[]), "nobody signed in");
        assert!(!ready(std::slice::from_ref(&g)), "signed in but Remote Desktop never connected");
        g.last_connected = Some(1);
        assert!(ready(&[g]));

        let fw = DryRun::default();
        apply(&fw, &store).unwrap();
        assert!(fw.locked_down.load(Ordering::SeqCst));
        assert!(!store.load().unwrap().protection_pending);
        std::fs::remove_dir_all(&dir).ok();
    }
}
