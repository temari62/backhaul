//go:build darwin && cgo

// Command backhaul-app-mac is the all-in-one macOS desktop app: one binary
// with a WKWebView UI (the shared internal/webui page), the exit node
// ("Share") and client ("Connect") built in via internal/gui.Backend. It is
// the macOS counterpart of cmd/backhaul-app (Windows).
//
// Serve/Connect change routes, DNS and the pf firewall, so they need root —
// but the GUI itself stays unprivileged (a root GUI is unsupported on macOS
// and cannot even see the user's pasteboard). The privileged work runs in a
// separate engine process, started with an administrator prompt on each
// Start; see internal/engine, elevate_darwin.go and README "macOS app".
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	webview "github.com/webview/webview_go"

	"backhaul/internal/app"
	"backhaul/internal/buildinfo"
	"backhaul/internal/config"
	"backhaul/internal/engine"
	"backhaul/internal/gui"
	"backhaul/internal/update"
	"backhaul/internal/webui"
)

const windowTitle = "Backhaul"

// rpcShim gives the page `bh(method, ...args) → Promise`, resolved later from
// a goroutine via __bhDone. Identical to the Windows app's bridge so the
// shared UI works unchanged.
const rpcShim = `
(() => {
  let seq = 0; const pending = {};
  window.__bhDone = (id, ok, v) => { const p = pending[id]; delete pending[id]; if (!p) return; ok ? p.res(v) : p.rej(new Error(v)); };
  window.bh = (m, ...a) => new Promise((res, rej) => { const id = ++seq; pending[id] = { res, rej }; window.__bh(id, m, JSON.stringify(a)); });
})();`

// updateBannerJS shows a bar when a newer release exists. On macOS the update
// is delivered as a .dmg, so the button opens the releases page rather than
// self-installing (see applyUpdate).
const updateBannerJS = `
(() => {
  window.addEventListener('load', () => setTimeout(async () => {
    let st; try { st = await bh('updateCheck'); } catch (e) { return; }
    if (!st || !st.available) return;
    const bar = document.createElement('div');
    bar.style.cssText = 'position:fixed;left:0;right:0;top:0;z-index:99999;display:flex;align-items:center;gap:10px;' +
      'padding:8px 12px;font:13px -apple-system,system-ui,sans-serif;color:#fff;' +
      'background:linear-gradient(90deg,#4f46e5,#06b6d4);box-shadow:0 1px 6px rgba(0,0,0,.25)';
    const msg = document.createElement('span'); msg.style.cssText = 'flex:1';
    msg.textContent = 'Backhaul ' + st.latest + ' is available.';
    const go = document.createElement('button'); go.textContent = 'Get update';
    go.style.cssText = 'border:0;border-radius:6px;padding:4px 12px;cursor:pointer;font:inherit;font-weight:600;background:#fff;color:#3730a3';
    go.onclick = () => bh('updateApply').catch(()=>{});
    const x = document.createElement('button'); x.textContent = '✕'; x.title = 'Dismiss';
    x.style.cssText = 'border:0;background:transparent;color:#fff;cursor:pointer;font:inherit';
    x.onclick = () => bar.remove();
    bar.append(msg, go, x);
    document.body.appendChild(bar);
  }, 1500));
})();`

// hideCustomTitlebarCSS hides only the page's own minimize/close buttons. The
// shared UI's header doubles as a custom title bar for the frameless Windows
// window; on macOS the native title bar and traffic-light buttons are kept, so
// just those two buttons are hidden to avoid doubling up (they are no-ops on
// macOS anyway). The Connect/Share tabs and the Help/Settings buttons — all
// inside the same header — must stay visible, so the header itself is NOT
// hidden.
const hideCustomTitlebarCSS = `
(() => {
  const css = '.winbtn.close,.winbtn[onclick*="minimize"]{display:none !important;}';
  const add = () => { const s = document.createElement('style'); s.textContent = css; document.head.appendChild(s); };
  if (document.head) add(); else window.addEventListener('DOMContentLoaded', add);
})();`

func main() {
	if engine.IsInvocation() {
		engine.Main(os.Args[2:]) // the privileged side; never returns
	}

	base, err := config.DefaultDir()
	if err != nil {
		fatal(err.Error())
	}
	dataDir := appDataDir()
	logs := setupLogging(dataDir)

	backend := &gui.Backend{
		Base: base,
		Logs: logs,
		Prepare: func(c *config.Config) error {
			// macOS downloads the pinned wstunnel/Xray on first use (the CLI
			// path), so no bundled paths are set here.
			if m := os.Getenv("BACKHAUL_NAT_MODE"); m != "" {
				c.Serve.NATMode = m
			}
			return nil
		},
		// Serve/Connect run as root in a separate engine process (see
		// internal/engine); this GUI stays unprivileged.
		Run: engine.Run(logs, launchViaOsascript),
		// Without this the badge would say "not administrator" for a GUI that
		// is unprivileged on purpose: rights are obtained per Start instead.
		IsAdmin: func() bool { return true },
	}

	// Anything a crash left behind (routes, DNS, pf) is repaired by the
	// engine's own pre-flight, as root, the next time it starts; the undo
	// journal is root-owned, so this process could not read it anyway.

	w := webview.New(os.Getenv("BACKHAUL_APP_DEBUG") != "")
	defer w.Destroy()
	w.SetTitle(windowTitle)
	w.SetSize(560, 600, webview.HintNone)
	w.SetSize(440, 420, webview.HintMin)

	ui := &rpc{w: w, b: backend}
	if err := w.Bind("__bh", ui.call); err != nil {
		fatal(err.Error())
	}
	w.Init(rpcShim)
	w.Init(hideCustomTitlebarCSS)
	w.Init(updateBannerJS)
	w.SetHtml(webui.IndexHTML)
	// Install the menu bar (⌘X/⌘C/⌘V/⌘A) so paste works in the text fields.
	// Dispatch runs it on the main thread once the run loop starts, after the
	// webview's own setup, so our Edit menu is the one that sticks.
	w.Dispatch(installEditMenu)
	slog.Info("Backhaul started", "config", base, "version", buildinfo.Version)
	w.Run()

	// Window closed: put the network back before exiting.
	backend.StopAndWait(app.MaxShutdown)
}

// rpc bridges the page's bh(method, args) calls to gui.Backend.
type rpc struct {
	w webview.WebView
	b *gui.Backend
}

// call is bound as window.__bh(id, method, argsJSON). It returns at once and
// resolves the page's promise later from a goroutine (so slow operations
// never freeze the window), mirroring the Windows app.
func (r *rpc) call(id int, method string, argsJSON string) {
	go func() {
		var args []json.RawMessage
		_ = json.Unmarshal([]byte(argsJSON), &args)
		res, err := r.dispatch(method, args)
		ok, payload := true, any(res)
		if err != nil {
			ok, payload = false, err.Error()
		}
		b, mErr := json.Marshal(payload)
		if mErr != nil {
			ok, b = false, []byte(`"internal error"`)
		}
		js := fmt.Sprintf("window.__bhDone(%d,%t,%s)", id, ok, b)
		r.w.Dispatch(func() { r.w.Eval(js) })
	}()
}

func (r *rpc) dispatch(method string, a []json.RawMessage) (any, error) {
	str := func(i int) string {
		var s string
		if i < len(a) {
			_ = json.Unmarshal(a[i], &s)
		}
		return s
	}
	num := func(i int) int {
		var n int
		if i < len(a) {
			_ = json.Unmarshal(a[i], &n)
		}
		return n
	}
	flag := func(i int) bool {
		var v bool
		if i < len(a) {
			_ = json.Unmarshal(a[i], &v)
		}
		return v
	}
	switch method {
	case "state":
		return r.b.State(), nil
	case "logs":
		return r.b.Logs.After(num(0)), nil
	case "detectIP":
		return r.b.DetectPublicIP()
	case "setupServe":
		return r.b.SetupServe(str(0), num(1), str(2), str(3))
	case "getPairing":
		return r.b.GetPairing()
	case "importPairing":
		return nil, r.b.ImportPairing(str(0))
	case "setKillSwitch":
		return nil, r.b.SetKillSwitch(flag(0))
	case "reset":
		return nil, r.b.Reset(str(0))
	case "start":
		return nil, r.b.Start(str(0))
	case "stop":
		r.b.Stop()
		return nil, nil
	case "addNode":
		return r.b.AddNode(str(0), str(1))
	case "selectNode":
		return nil, r.b.SelectNode(str(0))
	case "renameNode":
		return nil, r.b.RenameNode(str(0), str(1))
	case "removeNode":
		return nil, r.b.RemoveNode(str(0))
	case "clearError":
		r.b.ClearError()
		return nil, nil
	case "updateCheck":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return update.Check(ctx)
	case "updateApply":
		// The macOS update is a .dmg; open the releases page to download it.
		_ = exec.Command("open", "https://github.com/"+update.Repo+"/releases/latest").Start()
		return nil, nil
	case "version":
		return buildinfo.Version, nil
	case "quit":
		r.w.Dispatch(r.w.Terminate)
		return nil, nil
	// Window-chrome and Windows-only settings the shared page may call: these
	// are native or not applicable on macOS, so they are harmless no-ops.
	case "ready", "hide", "minimize", "drag":
		return nil, nil
	case "getStealth", "getAutostart":
		return false, nil
	case "setStealth", "setAutostart":
		return nil, nil
	}
	return nil, fmt.Errorf("unknown method %q", method)
}

// appDataDir is ~/Library/Application Support/Backhaul.
func appDataDir() string {
	base, err := os.UserConfigDir() // ~/Library/Application Support on macOS
	if err != nil || base == "" {
		base = os.TempDir()
	}
	d := filepath.Join(base, "Backhaul")
	_ = os.MkdirAll(d, 0o755)
	return d
}

func setupLogging(dataDir string) *gui.LogBuffer {
	const logMaxBytes = 5 << 20
	p := filepath.Join(dataDir, "backhaul.log")
	if st, err := os.Stat(p); err == nil && st.Size() > logMaxBytes {
		_ = os.Rename(p, p+".old")
	}
	var out io.Writer // nil if the log file can't be opened: UI-only logging
	if f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		out = f
	}
	lb := gui.NewLogBuffer(500, out, slog.LevelInfo)
	slog.SetDefault(slog.New(lb))
	return lb
}

func fatal(msg string) {
	slog.Error(msg)
	// A dialog so the user sees it even without a console.
	_ = exec.Command("osascript", "-e",
		fmt.Sprintf(`display alert "Backhaul" message %s as critical`, asQuote(msg))).Run()
	os.Exit(1)
}
