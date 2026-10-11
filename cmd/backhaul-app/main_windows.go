//go:build windows

// Command backhaul-app is the all-in-one Windows desktop app: one exe with a
// WebView2 UI, the exit node ("Share") and client ("Connect") built in, and
// wstunnel + Wintun embedded. It requests administrator rights via its
// manifest (connecting changes routes, DNS and the firewall).
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unsafe"

	"fyne.io/systray"
	webview2 "github.com/jchv/go-webview2"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"backhaul/internal/app"
	"backhaul/internal/config"
	"backhaul/internal/gui"
	"backhaul/internal/wg"
)

//go:embed ui/index.html
var indexHTML string

//go:embed bundle/wstunnel.exe
var wstunnelExe []byte

//go:embed bundle/xray.exe
var xrayExe []byte

//go:embed bundle/wintun.dll
var wintunDLL []byte

const (
	windowTitle = "Backhaul"
	mutexName   = `Local\BackhaulDesktopApp`
	logMaxBytes = 5 << 20
)

// rpcShim gives the page `bh(method, ...args) → Promise`. Calls are handled
// on Go goroutines so slow operations never freeze the window.
const rpcShim = `
(() => {
  let seq = 0; const pending = {};
  window.__bhDone = (id, ok, v) => { const p = pending[id]; delete pending[id]; if (!p) return; ok ? p.res(v) : p.rej(new Error(v)); };
  window.bh = (m, ...a) => new Promise((res, rej) => { const id = ++seq; pending[id] = { res, rej }; window.__bh(id, m, JSON.stringify(a)); });
})();`

func main() {
	if !singleInstance() {
		return
	}
	dataDir := appDataDir()
	logs := setupLogging(dataDir)

	wstPath, xrayPath, err := installBundle(dataDir)
	if err != nil {
		fatal("Backhaul could not unpack its components:\n\n" + err.Error())
	}
	base, err := config.DefaultDir()
	if err != nil {
		fatal(err.Error())
	}
	backend := &gui.Backend{
		Base: base,
		Logs: logs,
		Prepare: func(c *config.Config) error {
			c.Transport.WstunnelPath = wstPath
			c.Transport.XrayPath = xrayPath
			if m := os.Getenv("BACKHAUL_NAT_MODE"); m != "" { // power users / tests
				c.Serve.NATMode = m
			}
			return nil
		},
	}
	// Repair anything left by a crash before the user starts again.
	recoverCtx, cancelRecover := context.WithTimeout(context.Background(), app.TeardownTimeout)
	for _, dir := range backend.ProfileDirs() {
		if n, err := app.Recover(recoverCtx, config.Paths{Dir: dir}); n > 0 || err != nil {
			slog.Info("restored network settings left by a previous run", "profile", dir, "steps", n, "err", err)
		}
	}
	cancelRecover()

	unhook := hookMainWindow() // frameless and hidden from the first moment
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		AutoFocus: true,
		DataPath:  filepath.Join(dataDir, "WebView2"),
		WindowOptions: webview2.WindowOptions{
			Title: windowTitle, Width: 560, Height: 600, IconId: 1, Center: true,
		},
	})
	unhook()
	if w == nil {
		fatal("Backhaul needs the Microsoft Edge WebView2 Runtime.\n\nInstall it from:\nhttps://go.microsoft.com/fwlink/p/?LinkId=2124703\n\nthen start Backhaul again.")
	}
	defer w.Destroy()
	w.SetSize(544, 561, webview2.HintNone) // + frame allowance = 560×600 (the frame itself is hidden)
	w.SetSize(440, 420, webview2.HintMin)
	hwnd := uintptr(w.Window())
	applyTitleBarTheme(windows.HWND(hwnd))
	customFrame(hwnd)
	runTray(w, backend)
	if launchedByAutostart() {
		procShowWindow.Call(hwnd, swHide) // start in the tray
		uncloak(hwnd)
		if backend.State().Serve.Configured {
			go func() {
				if err := backend.Start(gui.RoleServe); err != nil {
					slog.Error("could not start sharing automatically", "err", err)
				}
			}()
		}
	} else {
		go refreshAutostart()
		// Show once the page has drawn (it calls "ready"), or after 3s regardless.
		time.AfterFunc(3*time.Second, func() {
			if startHidden.Load() {
				w.Dispatch(func() { showMain(hwnd) })
			}
		})
	}

	ui := &rpc{w: w, b: backend}
	if err := w.Bind("__bh", ui.call); err != nil {
		fatal(err.Error())
	}
	w.Init(rpcShim)
	if out := os.Getenv("BACKHAUL_APP_SELFTEST"); out != "" {
		ui.selftestOut = out
		if hold := os.Getenv("BACKHAUL_APP_SELFTEST_HOLD"); hold != "" {
			w.Init("window.__selftestHold = " + strconv.Quote(hold) + " * 1;")
		}
		if tr := os.Getenv("BACKHAUL_APP_SELFTEST_TRANSPORT"); tr != "" {
			w.Init("window.__selftestTransport = " + strconv.Quote(tr) + ";")
		}
		w.Init(selftestJS)
	}
	w.SetHtml(indexHTML)
	slog.Info("Backhaul started", "config", base)
	w.Run()

	// Quit chosen: always put the network back before exiting.
	backend.StopAndWait(app.MaxShutdown)
	systray.Quit()
}

type rpc struct {
	w           webview2.WebView
	b           *gui.Backend
	selftestOut string
}

// selftestJS drives the real page through the real RPC bridge and reports
// what it saw (BACKHAUL_APP_SELFTEST=<file>); used by automated smoke tests.
const selftestJS = `
window.addEventListener('load', () => setTimeout(async () => {
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const $ = (id) => document.getElementById(id);
  const r = { title: document.title, cards: !!$('cardServe') && !!$('cardConnect'), steps: [] };
  const step = (s) => r.steps.push(s);
  try {
    r.initial = await bh('state');
    try { await bh('nope'); } catch (e) { r.unknownRejects = true; }
    r.serveSetupVisible = !$('serveSetup').hidden;
    // Share flow, driven through the real UI controls.
    $('srvHost').value = '127.0.0.1'; $('srvPort').value = '18443';
    if (window.__selftestTransport) $('srvTransport').value = window.__selftestTransport;
    await setupServe(); step('setup');
    r.pairingDialogOpen = $('pairDlg').open; r.pairingLen = $('pairText').value.length; r.qrShown = !$('pairQR').hidden;
    await sleep(2500); $('pairDlg').close();                 // screenshot window: pairing dialog
    $('pairCode').value = $('pairText').value; await importCode(); step('import');
    await toggle('serve'); step('start');
    for (let i = 0; i < 40 && !(S && S.running === 'serve' && S.uptime); i++) await sleep(500);
    r.whileRunning = { running: S.running, phase: S.phase, hero: $('heroTitle').textContent, button: $('serveBtn').textContent, connectDisabled: $('connectBtn').disabled };
    const holdUntil = Date.now() + (window.__selftestHold || 3) * 1000; r.phasesSeen = [];
    while (Date.now() < holdUntil) { if (S && !r.phasesSeen.includes(S.phase)) r.phasesSeen.push(S.phase); await sleep(500); }
    r.peak = { phase: S.phase, hero: $('heroTitle').textContent, rx: S.rx, tx: S.tx, handshake: S.handshake };
    await toggle('serve'); step('stop');
    for (let i = 0; i < 60 && S && S.running; i++) await sleep(500);
    r.afterStop = { running: S.running, phase: S.phase, error: S.error || '' };
    r.logLines = $('log').childNodes.length;
  } catch (e) { r.error = String(e && e.message || e); }
  await bh('__selftest', JSON.stringify(r));
}, 2000));`

// call is bound as window.__bh(id, method, argsJSON). It returns at once and
// resolves the page's promise later from a goroutine.
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
	case "getAutostart":
		return autostartEnabled()
	case "setAutostart":
		return nil, setAutostart(flag(0))
	case "ready":
		if startHidden.Load() {
			r.w.Dispatch(func() { showMain(uintptr(r.w.Window())) })
		}
		return nil, nil
	case "hide":
		r.w.Dispatch(func() { procShowWindow.Call(uintptr(r.w.Window()), swHide) })
		return nil, nil
	case "minimize":
		r.w.Dispatch(func() { procShowWindow.Call(uintptr(r.w.Window()), swMinimize) })
		return nil, nil
	case "drag":
		hit := num(0)
		r.w.Dispatch(func() { beginDrag(uintptr(r.w.Window()), hit) })
		return nil, nil
	case "clearError":
		r.b.ClearError()
		return nil, nil
	case "__selftest":
		if r.selftestOut == "" {
			break
		}
		err := os.WriteFile(r.selftestOut, []byte(str(0)), 0o644)
		// Terminate posts WM_QUIT to the calling thread, so run it on the UI thread.
		time.AfterFunc(2*time.Second, func() { r.w.Dispatch(r.w.Terminate) })
		return nil, err
	}
	return nil, fmt.Errorf("unknown method %q", method)
}

// appDataDir is %LOCALAPPDATA%\Backhaul.
func appDataDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base, _ = os.UserCacheDir()
	}
	d := filepath.Join(base, "Backhaul")
	_ = os.MkdirAll(d, 0o755)
	return d
}

func setupLogging(dataDir string) *gui.LogBuffer {
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

// installBundle unpacks the embedded wstunnel, Xray and Wintun into
// %LOCALAPPDATA%\Backhaul\bin and returns the wstunnel path.
func installBundle(dataDir string) (wst, xray string, err error) {
	bin := filepath.Join(dataDir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		return "", "", err
	}
	wst = filepath.Join(bin, "wstunnel-"+config.DefaultWstunnelVersion+".exe")
	if err := unpack(wst, wstunnelExe); err != nil {
		return "", "", err
	}
	xray = filepath.Join(bin, "xray-"+config.DefaultXrayVersion+".exe")
	if err := unpack(xray, xrayExe); err != nil {
		return "", "", err
	}
	if err := wg.InstallWintun(wintunDLL); err != nil {
		return "", "", fmt.Errorf("wintun: %w", err)
	}
	return wst, xray, nil
}

// unpack writes an embedded executable unless an identical-size copy exists.
func unpack(dst string, data []byte) error {
	if st, err := os.Stat(dst); err == nil && st.Size() == int64(len(data)) {
		return nil
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// singleInstance focuses an already-open window instead of starting twice.
func singleInstance() bool {
	name, _ := windows.UTF16PtrFromString(mutexName)
	_, err := windows.CreateMutex(nil, false, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		title, _ := windows.UTF16PtrFromString(windowTitle)
		if h, _, _ := procFindWindowW.Call(0, uintptr(unsafe.Pointer(title))); h != 0 {
			showWindow(h) // also when it is hidden in the tray
		}
		return false
	}
	return true
}

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	procFindWindowW         = user32.NewProc("FindWindowW")
	procShowWindow          = user32.NewProc("ShowWindow")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procMessageBoxW         = user32.NewProc("MessageBoxW")
	dwmapi                  = windows.NewLazySystemDLL("dwmapi.dll")
	procDwmSetWindowAttr    = dwmapi.NewProc("DwmSetWindowAttribute")
)

// applyTitleBarTheme gives the native title bar a dark look when Windows
// apps use dark mode, so it matches the page.
func applyTitleBarTheme(hwnd windows.HWND) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	light, _, err := k.GetIntegerValue("AppsUseLightTheme")
	if err != nil || light != 0 {
		return
	}
	const dwmwaUseImmersiveDarkMode = 20
	on := int32(1)
	procDwmSetWindowAttr.Call(uintptr(hwnd), dwmwaUseImmersiveDarkMode, uintptr(unsafe.Pointer(&on)), unsafe.Sizeof(on))
}

func fatal(msg string) {
	slog.Error(msg)
	t, _ := windows.UTF16PtrFromString(windowTitle)
	m, _ := windows.UTF16PtrFromString(msg)
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), 0x10 /* MB_ICONERROR */)
	os.Exit(1)
}
