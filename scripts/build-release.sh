#!/usr/bin/env bash
# Builds release packages into dist/ from a Mac:
#   RDP-Gate-<v>-macOS.dmg / .zip    RDP Gate.app + rdpgate CLI
#   RDP-Gate-<v>-Windows-Client.zip  RDP Gate.exe + rdpgate.exe
#   RDP-Gate-<v>-Windows-Server.zip  rdpgate-server.exe + RDP Gate Server.exe + rdpgate-tray.exe + installer scripts
# Windows binaries are cross-compiled with cargo-xwin (cargo install cargo-xwin).
# The Setup installers (Inno Setup) and signed update manifest are only made
# by GitHub Actions (.github/workflows/release.yml), which is how releases ship.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
DIST=dist
WIN=x86_64-pc-windows-msvc
rm -rf "$DIST"
mkdir -p "$DIST"

echo "==> macOS ($VERSION)"
MAC_TARGETS=(aarch64-apple-darwin)
if rustup target list --installed | grep -q x86_64-apple-darwin; then
  MAC_TARGETS+=(x86_64-apple-darwin)
fi
for t in "${MAC_TARGETS[@]}"; do
  cargo build --release --target "$t" -p rdpgate-app -p rdpgate-client
done
MAC="$DIST/RDP-Gate-$VERSION-macOS"
APP="$MAC/RDP Gate.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
lipo_or_copy() { # $1 = binary name, $2 = destination
  local inputs=()
  for t in "${MAC_TARGETS[@]}"; do inputs+=("target/$t/release/$1"); done
  if [ "${#inputs[@]}" -gt 1 ]; then lipo -create -output "$2" "${inputs[@]}"; else cp "${inputs[0]}" "$2"; fi
}
lipo_or_copy rdpgate-app "$APP/Contents/MacOS/rdpgate-app"
lipo_or_copy rdpgate "$MAC/rdpgate"
sed "s/__VERSION__/$VERSION/g" packaging/macos/Info.plist > "$APP/Contents/Info.plist"
if [ -f packaging/macos/AppIcon.icns ]; then cp packaging/macos/AppIcon.icns "$APP/Contents/Resources/"; fi
# Ad-hoc signature: required for Apple Silicon. Not notarized, so a downloaded
# copy needs right-click > Open the first time (see README).
codesign --force --deep --sign - "$APP" 2>/dev/null || true
codesign --force --sign - "$MAC/rdpgate" 2>/dev/null || true
(cd "$DIST" && ditto -c -k --keepParent "RDP-Gate-$VERSION-macOS" "RDP-Gate-$VERSION-macOS.zip")
DMG_ROOT=$(mktemp -d)
cp -R "$APP" "$DMG_ROOT/" && cp "$MAC/rdpgate" "$DMG_ROOT/" && ln -s /Applications "$DMG_ROOT/Applications"
hdiutil create -quiet -volname "RDP Gate $VERSION" -srcfolder "$DMG_ROOT" -ov -format UDZO "$DIST/RDP-Gate-$VERSION-macOS.dmg"
rm -rf "$DMG_ROOT"

echo "==> Windows ($WIN)"
cargo xwin build --release --target "$WIN" -p rdpgate-server -p rdpgate-server-app -p rdpgate-tray -p rdpgate-client -p rdpgate-app
WC="$DIST/RDP-Gate-$VERSION-Windows-Client"
WS="$DIST/RDP-Gate-$VERSION-Windows-Server"
mkdir -p "$WC" "$WS"
cp "target/$WIN/release/rdpgate-app.exe" "$WC/RDP Gate.exe"
cp "target/$WIN/release/rdpgate.exe" "$WC/rdpgate.exe"
cp "target/$WIN/release/rdpgate-server.exe" "$WS/"
cp "target/$WIN/release/rdpgate-server-app.exe" "$WS/RDP Gate Server.exe"
cp "target/$WIN/release/rdpgate-tray.exe" "$WS/"
cp packaging/windows/install-server.ps1 packaging/windows/uninstall-server.ps1 packaging/windows/README.txt "$WS/"
(cd "$DIST" && zip -qr "RDP-Gate-$VERSION-Windows-Client.zip" "RDP-Gate-$VERSION-Windows-Client" \
                && zip -qr "RDP-Gate-$VERSION-Windows-Server.zip" "RDP-Gate-$VERSION-Windows-Server")

(cd "$DIST" && shasum -a 256 ./*.zip ./*.dmg > SHA256SUMS.txt)
echo "==> done"
ls -lh "$DIST"/*.zip "$DIST"/*.dmg
cat "$DIST/SHA256SUMS.txt"
