//go:build !darwin && !linux && !freebsd && !netbsd && !openbsd

package main

// Non-Unix platforms: skip mlock. The scrub path still zero-fills the
// buffer; memory pinning is just an additional defense against swap-to-disk
// that we can't guarantee here.

func mlock(_ []byte) error   { return nil }
func munlock(_ []byte) error { return nil }
