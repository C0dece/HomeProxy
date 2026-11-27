//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

type childJob struct{}

func prepareChild(_ *exec.Cmd) (childJob, error) { return childJob{}, nil }
func (childJob) attach(_ int) error              { return nil }
func (childJob) close()                          {}

func lockFile(f *os.File) error { return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) }

func startDetached(_ string, _ ...string) error {
	return errors.New("server self-update is only supported on Windows")
}
