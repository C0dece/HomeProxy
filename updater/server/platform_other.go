//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func openInstallation() (installation, func(), error) {
	return installation{}, nil, errors.New("service updates are available on Windows")
}

func lockUpdate(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }

func replaceFile(from, to string) error  { return os.Rename(from, to) }
func replaceImage(from, to string) error { return replaceFile(from, to) }

func hideConsole(_ *exec.Cmd) {}
