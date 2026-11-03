#!/usr/bin/env bash
# Builds the Linux desktop app:
#   dist/backhaul-app_linux_<arch>   the app (WebKitGTK UI via cgo)
#   dist/backhaul-app.desktop        launcher entry
#   dist/backhaul.png                its icon
#
#   ./build-app-linux.sh             # version from the VERSION file
#   ./build-app-linux.sh 0.5.0       # explicit version
#   ./build-app-linux.sh --install   # ...then install for the current user:
#                                    # ~/.local/bin, ~/.local/share/{applications,icons}
#
# Must run on Linux with Go 1.26+ and the GTK/WebKitGTK headers; on Ubuntu
# and Debian:
#   sudo apt install build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev
set -euo pipefail
cd "$(dirname "$0")"

VERSION="" INSTALL=0
for a in "$@"; do
  case "$a" in
    --install) INSTALL=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) VERSION="$a" ;;
  esac
done
if [ -z "$VERSION" ]; then
  VERSION="$(tr -d '[:space:]' < VERSION 2>/dev/null || true)"
  [ -n "$VERSION" ] || VERSION="dev"
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "build-app-linux.sh must run on Linux (needs cgo WebKitGTK)." >&2
  exit 1
fi
if ! command -v go >/dev/null; then
  echo "go not found. Ubuntu's apt Go is too old for this repo (needs 1.26+); install from https://go.dev/dl/:" >&2
  echo "  sudo tar -C /usr/local -xzf go1.26.1.linux-amd64.tar.gz && export PATH=\$PATH:/usr/local/go/bin" >&2
  exit 1
fi
if ! command -v pkg-config >/dev/null || ! pkg-config --exists gtk+-3.0; then
  echo "GTK headers missing: sudo apt install build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.1-dev" >&2
  exit 1
fi
# webview_go asks pkg-config for webkit2gtk-4.0, which Ubuntu 24.04+ no longer
# ships (only 4.1: same headers and API). With 4.1 installed, a shim .pc on
# PKG_CONFIG_PATH answers that request with 4.1's flags.
if pkg-config --exists webkit2gtk-4.1; then
  export PKG_CONFIG_PATH="$PWD/cmd/backhaul-app-linux/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
elif ! pkg-config --exists webkit2gtk-4.0; then
  echo "WebKitGTK headers missing: sudo apt install libwebkit2gtk-4.1-dev" >&2
  exit 1
fi

ARCH="$(go env GOARCH)"
BIN="dist/backhaul-app_linux_$ARCH"
mkdir -p dist

echo "1/3  Building the app (cgo WebKitGTK), version $VERSION..."
CGO_ENABLED=1 go build -trimpath -tags gtk \
  -ldflags "-s -w -X backhaul/internal/buildinfo.Version=$VERSION" \
  -o "$BIN" ./cmd/backhaul-app-linux

echo "2/3  Drawing the icon..."
go run ./cmd/backhaul-app/gen -icon-only -size 256 -out dist/backhaul.png

echo "3/3  Writing the launcher entry..."
# Exec is the installed path: --install's, or the system-wide one otherwise.
EXEC="/usr/local/bin/backhaul-app"
[ "$INSTALL" = 1 ] && EXEC="$HOME/.local/bin/backhaul-app"
# The file is named after the app id the window reports (backhaul-app, set in
# gtk_linux.go), and says so again in StartupWMClass: that is how GNOME pairs
# the running window with this entry's icon and name in the dock.
cat > dist/backhaul-app.desktop <<DESKTOP
[Desktop Entry]
Type=Application
Version=1.0
Name=Backhaul
Comment=Share this computer's internet with your other devices, or connect to your exit node
Exec=$EXEC
Icon=backhaul
Terminal=false
Categories=Network;
Keywords=VPN;tunnel;exit node;
StartupWMClass=backhaul-app
DESKTOP

if [ "$INSTALL" = 1 ]; then
  echo "Installing for $USER..."
  install -Dm755 "$BIN" "$HOME/.local/bin/backhaul-app"
  install -Dm644 dist/backhaul.png "$HOME/.local/share/icons/hicolor/256x256/apps/backhaul.png"
  install -Dm644 dist/backhaul-app.desktop "$HOME/.local/share/applications/backhaul-app.desktop"
  rm -f "$HOME/.local/share/applications/backhaul.desktop" # the entry's earlier name
  command -v update-desktop-database >/dev/null && update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
  echo "  Backhaul is in your app launcher; or run $HOME/.local/bin/backhaul-app"
fi

echo ""
echo "Done:"
echo "  $BIN ($(du -h "$BIN" | cut -f1))"
echo "  dist/backhaul-app.desktop, dist/backhaul.png"
sha256sum "$BIN" | sed 's#dist/##'
