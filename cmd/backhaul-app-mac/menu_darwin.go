//go:build darwin && cgo

// A WKWebView only receives the clipboard shortcuts (⌘X/⌘C/⌘V/⌘A) when the
// application has a menu bar whose Edit menu carries those key equivalents:
// macOS dispatches them through the main menu's responder chain, which ends at
// the focused text field. The webview_go library creates none, so paste into
// the Cloudflare-token and pairing-code fields did nothing. installEditMenu
// builds the standard menu bar (an app menu with Quit, and an Edit menu with
// the clipboard items) so those shortcuts reach the field.
package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa
#import <Cocoa/Cocoa.h>

static void installEditMenu(void) {
  @autoreleasepool {
    NSApplication *app = [NSApplication sharedApplication];
    NSMenu *menubar = [[NSMenu alloc] init];
    NSString *appName = [[NSProcessInfo processInfo] processName];

    // Application menu: without one the menu bar shows no app name and Quit
    // (⌘Q) has nowhere to live.
    NSMenuItem *appItem = [[NSMenuItem alloc] init];
    [menubar addItem:appItem];
    NSMenu *appMenu = [[NSMenu alloc] init];
    [appMenu addItemWithTitle:[@"Quit " stringByAppendingString:appName]
                       action:@selector(terminate:)
                keyEquivalent:@"q"];
    [appItem setSubmenu:appMenu];

    // Edit menu: the selectors (cut:/copy:/paste:/selectAll:/undo:/redo:) are
    // handled by the WKWebView's field editor when it is first responder.
    NSMenuItem *editItem = [[NSMenuItem alloc] init];
    [menubar addItem:editItem];
    NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"Edit"];
    [editMenu addItemWithTitle:@"Undo" action:@selector(undo:) keyEquivalent:@"z"];
    NSMenuItem *redo = [editMenu addItemWithTitle:@"Redo" action:@selector(redo:) keyEquivalent:@"z"];
    [redo setKeyEquivalentModifierMask:(NSEventModifierFlagCommand | NSEventModifierFlagShift)];
    [editMenu addItem:[NSMenuItem separatorItem]];
    [editMenu addItemWithTitle:@"Cut" action:@selector(cut:) keyEquivalent:@"x"];
    [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
    [editMenu addItemWithTitle:@"Paste" action:@selector(paste:) keyEquivalent:@"v"];
    [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
    [editItem setSubmenu:editMenu];

    [app setMainMenu:menubar];
  }
}
*/
import "C"

// installEditMenu installs the standard macOS menu bar. It touches AppKit, so
// it must run on the main thread (call it via webview's Dispatch).
func installEditMenu() { C.installEditMenu() }
