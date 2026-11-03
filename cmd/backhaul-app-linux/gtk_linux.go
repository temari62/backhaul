//go:build linux && cgo && gtk

package main

/*
#cgo pkg-config: gtk+-3.0
#include <gtk/gtk.h>

// GTK derives the window's app id (Wayland) and WM_CLASS (X11) from the
// program name, and GNOME matches that to backhaul-app.desktop for the dock
// icon and name; set it before gtk_init so it does not come from argv[0]
// (which is "backhaul-app_linux_amd64" when run from dist/).
static void bh_set_prgname(void) { g_set_prgname("backhaul-app"); }

// The window's own icon (X11 title bars and task lists; GNOME on Wayland
// takes it from the .desktop file instead). rgba is copied.
static void bh_set_icon(void *win, const unsigned char *rgba, int size) {
	GdkPixbuf *src = gdk_pixbuf_new_from_data(rgba, GDK_COLORSPACE_RGB, TRUE, 8, size, size, size * 4, NULL, NULL);
	GdkPixbuf *pb = gdk_pixbuf_copy(src);
	g_object_unref(src);
	gtk_window_set_icon(GTK_WINDOW(win), pb);
	gtk_window_set_default_icon(pb);
	g_object_unref(pb);
}

static gboolean bh_on_delete(GtkWidget *w, GdkEvent *e, gpointer data) {
	gtk_widget_hide(w);
	return TRUE; // handled here: the window is not destroyed, so the app lives on
}
static void bh_hide_on_close(void *win) {
	g_signal_connect(G_OBJECT(win), "delete-event", G_CALLBACK(bh_on_delete), NULL);
}
static void bh_show(void *win) {
	gtk_widget_show_all(GTK_WIDGET(win));
	gtk_window_present(GTK_WINDOW(win));
}
*/
import "C"

import (
	"image"
	"unsafe"
)

// setProgramName must run before webview.New (which runs gtk_init).
func setProgramName() { C.bh_set_prgname() }

// setWindowIcon gives the GTK window the logo. img must be square.
func setWindowIcon(win unsafe.Pointer, img *image.NRGBA) {
	C.bh_set_icon(win, (*C.uchar)(unsafe.Pointer(&img.Pix[0])), C.int(img.Rect.Dx()))
}

// hideOnClose makes the window's close button hide it instead of ending the
// app — only sensible when there is a tray icon to bring it back from.
func hideOnClose(win unsafe.Pointer) { C.bh_hide_on_close(win) }

// showWindow shows and raises the window. GTK main thread only (Dispatch).
func showWindow(win unsafe.Pointer) { C.bh_show(win) }
