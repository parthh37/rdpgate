# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
private reporting instead: **Security → Report a vulnerability** on this
repository. Include what you found, how to reproduce it, and what an attacker
could do with it. You'll get a reply within a week.

## Scope

In scope: anything that lets someone open the firewall, sign in, enroll a
device or passkey, read secrets, or crash the agent without being an enrolled
device or passkey holder. Also anything in the installer that leaves Remote
Desktop more exposed than documented.

Out of scope: attacks that need administrator access to the Windows server,
or an unlocked client together with its passphrase and second factor; the
documented limitation that a firewall grant applies to everyone sharing the
signed-in public IP address; and browser sign-in under a hijacked domain with
a live relay (desktop sign-in doesn't depend on DNS).

## Design summary

- **Mutual authentication without CAs or DNS.** The desktop protocol runs over
  TLS 1.3. Before the client sends anything, the server signs the TLS exporter
  value (RFC 8446 §7.5) with its Ed25519 identity key, which the client pinned
  from the server card. The client then signs its request over the same
  value with its device key. Neither message can be replayed or relayed.
- **Signatures are verified before any request content is parsed.**
- **Single use.** TOTP codes are single-use (the last accepted time step is
  stored), and 10 wrong codes lock that device. Each WebAuthn challenge is
  single-use, and passkeys require user verification.
- **The IP beacon** is signed by the server key, encrypted with
  XChaCha20-Poly1305 under a key only enrolled clients hold, and
  time-stamped. Clients reject beacons older than one they've seen. The
  public IP is only published when two independent sources agree.
- **The RDP endpoint is verified:** the server reports its RDP certificate
  fingerprint over the authenticated channel, and the client refuses to
  launch Remote Desktop if the RDP port presents a different one.
- **Pre-authentication limits.** Input is capped at 16 KiB (protocol) and
  64 KiB (web). Connections are capped per source and handshakes are
  time-limited. Failing sources are throttled, then silently dropped.
- **Firewall rules** are only ever *allow* rules for one public IP taken
  from the socket address. Private and carrier-NAT sources are refused by
  default, and UDP is opt-in. Leftover rules are removed before anything
  else at startup, and reconciled every few minutes.
- **The data folder** (identity key, TOTP secret, GitHub token) is owned by
  Administrators and readable by SYSTEM and Administrators only. This is
  enforced at every start.
- **The agent runs as LocalSystem** because it edits Windows Firewall rules.
  Privilege separation is on the roadmap.
