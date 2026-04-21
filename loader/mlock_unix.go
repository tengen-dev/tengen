//go:build darwin || linux || freebsd || netbsd || openbsd

package main

import "syscall"

func mlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return syscall.Mlock(b)
}

func munlock(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return syscall.Munlock(b)
}
