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

Optional browser sign-in with passkeys needs your own DNS name:
    .\install-server.ps1 -PublicHost rdp.example.com
    rdpgate-server passkey-enroll

Uninstall:  .\uninstall-server.ps1  (add -RemoveData to delete settings)

Full guide: https://github.com/parthh37/rdpgate
