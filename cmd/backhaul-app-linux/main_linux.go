//go:build linux && cgo && gtk

// Command backhaul-app-linux is the all-in-one Linux desktop app: one binary
// with a WebKitGTK UI (the shared internal/webui page), the exit node
// ("Share") and client ("Connect") built in via internal/gui.Backend. It is
// the Linux counterpart of cmd/backhaul-app (Windows) and
// cmd/backhaul-app-mac.
//
// Serve/Connect change routes, DNS and the firewall, so they need root — but
// the window stays unprivileged (a root GTK app cannot reach a Wayland
// session and leaves root-owned files in the user's home). The privileged
// work runs in a separate engine process, started through pkexec's
// authorization prompt on each Start; see internal/engine, elevate_linux.go
// and README "Linux desktop app". Launched as root (sudo) it runs the role
// in-process instead, like the Windows app.
//
// The GTK/WebKitGTK headers are only needed behind the "gtk" build tag, so a
// plain `go build ./...` stays dependency-free; build-app-linux.sh sets it.
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
	"backhaul/internal/logo"
	"backhaul/internal/tray"
	"backhaul/internal/update"
	"backhaul/internal/webui"
)

const windowTitle = "Backhaul"

// rpcShim gives the page `bh(method, ...args) → Promise`, resolved later from
// a goroutine via __bhDone. Identical to the Windows and macOS apps' bridge
// so the shared UI works unchanged.
const rpcShim = `
(() => {
  let seq = 0; const pending = {};
  window.__bhDone = (id, ok, v) => { const p = pending[id]; delete pending[id]; if (!p) return; ok ? p.res(v) : p.rej(new Error(v)); };
  window.bh = (m, ...a) => new Promise((res, rej) => { const id = ++seq; pending[id] = { res, rej }; window.__bh(id, m, JSON.stringify(a)); });
})();`

// updateBannerJS shows a bar when a newer release exists. There is no Linux
// installer to run, so the button opens the releases page (see applyUpdate).
const updateBannerJS = `
(() => {
  window.addEventListener('load', () => setTimeout(async () => {
    let st; try { st = await bh('updateCheck'); } catch (e) { return; }
    if (!st || !st.available) return;
    const bar = document.createElement('div');
    bar.style.cssText = 'position:fixed;left:0;right:0;top:0;z-index:99999;display:flex;align-items:center;gap:10px;' +
      'padding:8px 12px;font:13px system-ui,sans-serif;color:#fff;' +
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
// window; here the window manager draws the real title bar, so just those
// two buttons are hidden to avoid doubling up (they are no-ops here anyway).
// The Connect/Share tabs and the Help/Settings buttons — all inside the same
// header — must stay visible, so the header itself is NOT hidden.
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
	setProgramName() // before GTK starts: it is the app id the dock matches

	base, err := config.DefaultDir()
	if err != nil {
		fatal(err.Error())
	}
	logs := setupLogging(base)

	backend := &gui.Backend{
		Base: base,
		Logs: logs,
		Prepare: func(c *config.Config) error {
			// Linux downloads the pinned wstunnel/Xray/cloudflared on first use
			// (the CLI path), so no bundled paths are set here.
			if m := os.Getenv("BACKHAUL_NAT_MODE"); m != "" {
				c.Serve.NATMode = m
			}
			return nil
		},
	}
	if os.Geteuid() != 0 {
		// Serve/Connect run as root in a separate engine process (see
		// internal/engine); this GUI stays unprivileged. Without IsAdmin the
		// badge would say "not administrator" for a GUI that is unprivileged
		// on purpose: rights are obtained per Start instead.
		backend.Run = engine.Run(logs, launchViaPkexec)
		backend.IsAdmin = func() bool { return true }
	}

	// Anything a crash left behind (routes, DNS, nftables) is repaired by the
	// engine's own pre-flight, as root, the next time it starts.

	w := webview.New(os.Getenv("BACKHAUL_APP_DEBUG") != "")
	defer w.Destroy()
	w.SetTitle(windowTitle)
	setWindowIcon(w.Window(), logo.Draw(256, nil))
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
	// A tray icon, when this desktop can show one (GNOME needs the
	// AppIndicator extension; Ubuntu's session has it): closing the window
	// then keeps Backhaul running in the tray, as on Windows. Without one the
	// close button quits, so the app can never be running yet unreachable.
	if ok, hint := tray.HostAvailable(); ok {
		hideOnClose(w.Window())
		runTray(w, backend)
	} else {
		slog.Info("no system tray on this desktop; closing the window quits", "detail", hint)
	}
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
		// No installer on Linux; open the releases page to download it.
		_ = exec.Command("xdg-open", "https://github.com/"+update.Repo+"/releases/latest").Start()
		return nil, nil
	case "version":
		return buildinfo.Version, nil
	case "quit":
		r.w.Dispatch(r.w.Terminate)
		return nil, nil
	// Window-chrome and Windows-only settings the shared page may call: these
	// are native or not applicable on Linux, so they are harmless no-ops.
	case "ready", "hide", "minimize", "drag":
		return nil, nil
	case "getStealth", "getAutostart":
		return false, nil
	case "setStealth", "setAutostart":
		return nil, nil
	}
	return nil, fmt.Errorf("unknown method %q", method)
}

// setupLogging writes the app's own log beside the profiles
// (~/.config/backhaul/app.log) and mirrors it into the Activity panel.
func setupLogging(dir string) *gui.LogBuffer {
	const logMaxBytes = 5 << 20
	_ = os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, "app.log")
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
	// A dialog so the user sees it even when launched from a menu, if the
	// desktop has zenity (GNOME does); stderr otherwise.
	if _, err := exec.LookPath("zenity"); err == nil {
		_ = exec.Command("zenity", "--error", "--title=Backhaul", "--text="+msg).Run()
	} else {
		fmt.Fprintln(os.Stderr, "backhaul-app: "+msg)
	}
	os.Exit(1)
}
