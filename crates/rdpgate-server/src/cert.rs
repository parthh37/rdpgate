//! The browser portal's certificate, from PEM files the owner renews (with
//! their DNS provider's tooling, say). RDP Gate doesn't fetch one itself:
//! Let's Encrypt only checks over port 80 or 443, which it never uses.

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::watch;

/// How often the files are checked for a renewed certificate.
const RELOAD_EVERY: Duration = Duration::from_secs(3600);

/// Reads a certificate chain and its private key, and checks they belong
/// together and, with `host`, that the certificate covers it.
pub fn read(cert: &Path, key: &Path, host: Option<&str>) -> Result<CertifiedKey, String> {
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|i| i.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("{}: no certificate in the file", cert.display()));
    }
    let pk = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let provider = rustls::crypto::ring::default_provider();
    let ck = CertifiedKey::from_der(chain, pk, &provider)
        .map_err(|e| format!("{} and {} don't go together: {e}", cert.display(), key.display()))?;
    if let Some(host) = host {
        let name = ServerName::try_from(host).map_err(|e| format!("{host}: {e}"))?;
        webpki::EndEntityCert::try_from(&ck.cert[0])
            .and_then(|ee| ee.verify_is_valid_for_subject_name(&name))
            .map_err(|_| format!("the certificate in {} doesn't cover {host}", cert.display()))?;
    }
    Ok(ck)
}

fn modified(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// Serves the certificate in the files, and the renewed one once they change.
#[derive(Debug)]
pub struct FileCert {
    cert: PathBuf,
    key: PathBuf,
    current: RwLock<(Arc<CertifiedKey>, Option<SystemTime>, Option<SystemTime>)>,
}

impl FileCert {
    pub fn load(cert: &Path, key: &Path) -> Result<Arc<Self>, String> {
        let (cm, km) = (modified(cert), modified(key));
        let ck = read(cert, key, None)?;
        Ok(Arc::new(FileCert { cert: cert.into(), key: key.into(), current: RwLock::new((Arc::new(ck), cm, km)) }))
    }

    /// Reads the files again if they changed. A half-written renewal (the
    /// two files not matching yet) keeps the old certificate until the next
    /// check.
    fn reload(&self) {
        let (cm, km) = (modified(&self.cert), modified(&self.key));
        {
            let cur = self.current.read().unwrap();
            if (cur.1, cur.2) == (cm, km) {
                return;
            }
        }
        match read(&self.cert, &self.key, None) {
            Ok(ck) => {
                *self.current.write().unwrap() = (Arc::new(ck), cm, km);
                crate::logln!("CERT reloaded {}", self.cert.display());
            }
            Err(e) => crate::logln!("WARNING keeping the current browser certificate: {e}"),
        }
    }

    /// Checks the files every hour until `shutdown`.
    pub fn watch(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        tokio::spawn(async move {
            let mut t = tokio::time::interval(RELOAD_EVERY);
            t.tick().await;
            loop {
                tokio::select! {
                    _ = t.tick() => {
                        let me = self.clone();
                        let _ = tokio::task::spawn_blocking(move || me.reload()).await;
                    }
                    _ = shutdown.changed() => return,
                }
            }
        });
    }
}

impl ResolvesServerCert for FileCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().unwrap().0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_the_key_and_the_name() {
        let dir = std::env::temp_dir().join(format!("rdpgate-cert-{}", rdpgate_core::random_token::<6>()));
        std::fs::create_dir_all(&dir).unwrap();
        let make = |name: &str| {
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap().self_signed(&key).unwrap();
            let (c, k) = (dir.join(format!("{name}.pem")), dir.join(format!("{name}-key.pem")));
            std::fs::write(&c, cert.pem()).unwrap();
            std::fs::write(&k, key.serialize_pem()).unwrap();
            (c, k)
        };
        let (cert, key) = make("rdp.example.com");
        let (_, other_key) = make("other.example.com");
        read(&cert, &key, Some("rdp.example.com")).unwrap();
        read(&cert, &key, None).unwrap();
        assert!(read(&cert, &key, Some("rdp.example.org")).unwrap_err().contains("doesn't cover"));
        assert!(read(&cert, &other_key, None).unwrap_err().contains("don't go together"));
        assert!(read(&key, &key, None).is_err(), "a key file is no certificate");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
