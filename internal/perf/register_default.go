//go:build !(re2_cgo && libinjection_cgo)

package perf

// Register is a no-op for default builds.
func Register() {}
