//go:build re2_cgo && libinjection_cgo

package perf

import "github.com/corazawaf/coraza-wasilibs"

// Register enables the CGO-backed Coraza operator implementations.
func Register() {
	wasilibs.RegisterRX()
	wasilibs.RegisterSQLi()
	wasilibs.RegisterXSS()
}
