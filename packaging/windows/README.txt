RDP Gate server for Windows
===========================

Install (PowerShell as Administrator, in this folder):

    Set-ExecutionPolicy -Scope Process Bypass
    .\install-server.ps1

It asks for a GitHub token limited to "Gists: read and write", so your
computers can find this PC through an encrypted, signed beacon (no DNS name
or static IP needed). Then:

    rdpgate-server totp-setup                 # 6-digit codes for the app
    rdpgate-server device-add <name> <key>    # for each Mac/PC (the app shows this line)
    rdpgate-server status

Router: forward TCP 443 and TCP 3389 to this PC. Remote Desktop stays closed
until someone signs in.

Installing over Remote Desktop? Use -Protect AfterSignIn (the default inside a
Remote Desktop session): Remote Desktop stays reachable until one of your
computers has signed in through RDP Gate and connected, then the service
closes it to everyone else. "rdpgate-server protect" does it sooner.

Optional browser sign-in with passkeys needs your own domain name. Guided:
    rdpgate-server domain-setup

Uninstall:  .\uninstall-server.ps1 -Restore   (puts back what Setup changed;
            add -RemoveData to delete RDP Gate's data too)

Full guide: https://github.com/parthh37/rdpgate
