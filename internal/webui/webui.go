// Package webui holds the shared desktop UI: a single HTML page driven by an
// RPC bridge (window.bh(method, ...args) → Promise). Both the Windows app
// (cmd/backhaul-app) and the macOS app (cmd/backhaul-app-mac) embed it and
// bind the same methods to internal/gui.Backend, so the two front ends stay
// in lockstep.
package webui

import _ "embed"

// IndexHTML is the single-page UI served into the WebView.
//
//go:embed index.html
var IndexHTML string
