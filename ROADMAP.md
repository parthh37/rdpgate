# Roadmap

## v0.1: IP-based gate (current)

- [x] Windows agent: TLS 1.3 sign-in service
- [x] Desktop sign-in: Ed25519 device key (passphrase-encrypted) + one-time TOTP code
- [x] Pinned server identity: the server proves its key over the TLS channel binding before the client sends anything
- [x] Encrypted, signed IP beacon in a secret GitHub gist: no static IP, DNS name or DuckDNS
- [x] RDP certificate check before launching Remote Desktop (detects interception)
- [x] Optional browser sign-in with passkeys (own domain, automatic Let's Encrypt)
- [x] Per-IP Windows Firewall grants that stay while connected and expire on their own; private/NAT sources refused; UDP opt-in
- [x] Per-device lockout after 10 wrong codes
- [x] Installer that hardens RDP (NLA, TLS, CredSSP), the firewall (incl. Group Policy check) and the data folder
- [x] Mac and Windows desktop app plus `rdpgate` CLI
- [x] Setup wizards (Inno Setup) for the Windows server and client, a disk image for Mac
- [x] Automatic Windows Firewall configuration (self-healing) and router port forwarding via UPnP, with carrier-grade NAT detection
- [x] Signed auto-updates for server, apps and CLIs; one-click automated version bump and release

## v0.2: Tunnel mode

The biggest remaining weakness of v0.1 is that a firewall grant trusts an IP
address, and many people can share one (hotel Wi-Fi, carrier NAT).

- [ ] RDP carried inside the authenticated TLS connection: the client listens on
      `127.0.0.1`, every TCP connection is signed with the device key, and the
      agent splices it to `127.0.0.1:3389`
- [ ] No port 3389 forwarding at all; RDP blocked from every non-loopback address
- [ ] Browser approval for desktop sessions ("approve on your phone with a passkey")
- [ ] Keep IP mode for browsers and devices without the app

## Hardening

- [ ] Privilege separation: an unprivileged internet-facing process and a tiny
      firewall helper running as SYSTEM
- [ ] Code-signed Windows binaries and installers (Authenticode), notarized macOS app
- [ ] Release-key rotation built into the updater
- [ ] Device keys held in hardware: Secure Enclave (macOS), TPM (Windows)
- [ ] Optional "passkey **and** code" mode
- [ ] Beacon key rotation (`rdpgate-server beacon-rotate`) and per-device beacon encryption
- [ ] More beacon stores: your own HTTPS endpoint, S3/R2, DNS TXT on your own domain
- [ ] Windows Event Log output and log shipping
- [ ] Third-party security review

## Convenience

- [x] Keep the PC awake while someone is signed in
- [ ] Sign-in notifications (email / push) and a revoke link
- [ ] LAN allow-list (skip sign-in at home)
- [ ] IPv6 listening by default, with dual-stack grants
- [ ] NAT-PMP / PCP for routers without UPnP, and an outside-in reachability test
- [ ] Multiple users with their own devices and passkeys
- [ ] Small admin web page on the server (localhost only)

## Platforms

- [ ] Linux server (nftables) and macOS server (pf), for VNC/SSH as well as RDP
- [ ] Linux client app
