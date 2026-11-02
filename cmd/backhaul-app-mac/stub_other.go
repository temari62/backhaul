//go:build !darwin || !cgo

// The macOS app builds only on darwin (it needs WKWebView via cgo). This stub
// keeps `go build ./...` and `go vet ./...` working on other platforms.
package main

func main() {}
