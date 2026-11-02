#!/usr/bin/env bash
# Builds the macOS app and a drag-to-install disk image:
#   dist/Backhaul.app
#   dist/Backhaul-<version>.dmg
#
#   ./build-app-mac.sh            # version from the VERSION file
#   ./build-app-mac.sh 0.5.0      # explicit version
#
# Must run on macOS: the app embeds a WKWebView via cgo, and the icon/dmg use
# iconutil, sips and hdiutil. Requires Go 1.26+ and the Xcode command line
# tools (xcode-select --install).
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(tr -d '[:space:]' < VERSION 2>/dev/null || true)"
  [ -n "$VERSION" ] || VERSION="dev"
fi

if [ "$(uname -s)" != "Darwin" ]; then
  echo "build-app-mac.sh must run on macOS (needs cgo WKWebView, iconutil, hdiutil)." >&2
  exit 1
fi

APP="dist/Backhaul.app"
APPBIN="$APP/Contents/MacOS/Backhaul"
RES="$APP/Contents/Resources"

echo "1/5  Building the binary (cgo WKWebView), version $VERSION..."
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$RES"
CGO_ENABLED=1 go build -trimpath \
  -ldflags "-s -w -X backhaul/internal/buildinfo.Version=$VERSION" \
  -o "$APPBIN" ./cmd/backhaul-app-mac

echo "2/5  Drawing the app icon..."
ICONSET="dist/Backhaul.iconset"
rm -rf "$ICONSET"; mkdir -p "$ICONSET"
go run ./cmd/backhaul-app/gen -icon-only -size 1024 -out dist/icon1024.png
# The standard iconset sizes, downscaled from the 1024 master.
for sz in 16 32 128 256 512; do
  sips -z "$sz" "$sz"       dist/icon1024.png --out "$ICONSET/icon_${sz}x${sz}.png"        >/dev/null
  sips -z "$((sz*2))" "$((sz*2))" dist/icon1024.png --out "$ICONSET/icon_${sz}x${sz}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$RES/Backhaul.icns"
rm -rf "$ICONSET" dist/icon1024.png

echo "3/5  Writing Info.plist..."
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>            <string>Backhaul</string>
  <key>CFBundleDisplayName</key>     <string>Backhaul</string>
  <key>CFBundleIdentifier</key>      <string>llc.novawave.backhaul</string>
  <key>CFBundleVersion</key>         <string>$VERSION</string>
  <key>CFBundleShortVersionString</key> <string>$VERSION</string>
  <key>CFBundleExecutable</key>      <string>Backhaul</string>
  <key>CFBundleIconFile</key>        <string>Backhaul</string>
  <key>CFBundlePackageType</key>     <string>APPL</string>
  <key>LSMinimumSystemVersion</key>  <string>13.0</string>
  <key>NSHighResolutionCapable</key> <true/>
</dict>
</plist>
PLIST

echo "4/5  Signing (ad-hoc)..."
# Ad-hoc signature so Gatekeeper runs it after a right-click→Open. Replace with
# a Developer ID identity + notarization for distribution without that step.
codesign --force --deep --sign - "$APP" || echo "  (codesign failed; app still runs after right-click → Open)"

echo "5/5  Building the disk image..."
DMG="dist/Backhaul-$VERSION.dmg"
rm -f "$DMG"
STAGE="$(mktemp -d)"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "Backhaul" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE"

echo ""
echo "Done:"
echo "  $APP"
echo "  $DMG ($(du -h "$DMG" | cut -f1))"
shasum -a 256 "$DMG" | sed 's#dist/##'
