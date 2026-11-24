package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "HomeProxyServer"

type managedService struct{ service *mgr.Service }

func openInstallation() (installation, func(), error) {
	manager, err := mgr.Connect()
	if err != nil {
		return installation{}, nil, err
	}
	service, err := manager.OpenService(serviceName)
	if err != nil {
		manager.Disconnect()
		return installation{}, nil, err
	}
	closeService := func() {
		service.Close()
		manager.Disconnect()
	}
	config, err := service.Config()
	if err != nil {
		closeService()
		return installation{}, nil, err
	}
	args, err := windows.DecomposeCommandLine(config.BinaryPathName)
	if err != nil || config.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS || len(args) != 3 ||
		!filepath.IsAbs(args[0]) || !strings.EqualFold(filepath.Base(args[0]), "homeproxy-server.exe") ||
		args[1] != "-config" || !filepath.IsAbs(args[2]) {
		closeService()
		return installation{}, nil, errors.New("service must use homeproxy-server.exe -config with absolute paths")
	}
	image, configPath := filepath.Clean(args[0]), filepath.Clean(args[2])
	probe, err := localProbe(configPath)
	if err != nil {
		closeService()
		return installation{}, nil, err
	}
	return installation{
		service: managedService{service}, image: image, config: configPath,
		probe: probe, stateDir: filepath.Join(filepath.Dir(image), ".homeproxy-updates"), startTimeout: 30 * time.Second,
	}, closeService, nil
}

func (s managedService) pid() (int, error) {
	status, err := s.service.Query()
	if err != nil || status.State != svc.Running {
		return 0, err
	}
	return int(status.ProcessId), nil
}

func (s managedService) start(expected health) error {
	return s.service.Start("homeproxy-update", expected.Version, strconv.Itoa(expected.API), strconv.Itoa(expected.DBSchema))
}

func (s managedService) stop(ctx context.Context) error {
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	sent := false
	for {
		status, err := s.service.Query()
		if err != nil {
			return err
		}
		switch status.State {
		case svc.Stopped:
			return nil
		case svc.Running, svc.Paused:
			if !sent {
				if _, err := s.service.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
					return err
				}
				sent = true
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func lockUpdate(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &windows.Overlapped{})
}

func replaceFile(from, to string) error {
	source, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	dest, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return retryReplace(func() error {
		return windows.MoveFileEx(source, dest, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
	})
}

var replaceFileW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")

func replaceImage(from, to string) error {
	if _, err := os.Stat(to); errors.Is(err, os.ErrNotExist) {
		return replaceFile(from, to)
	} else if err != nil {
		return err
	}
	source, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	dest, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	// Preserve the installed executable's DACL, including service account access.
	return retryReplace(func() error {
		result, _, err := replaceFileW.Call(uintptr(unsafe.Pointer(dest)), uintptr(unsafe.Pointer(source)), 0, 0, 0, 0)
		if result != 0 {
			return nil
		}
		return err
	})
}

func retryReplace(replace func() error) error {
	for attempt := 0; ; attempt++ {
		err := replace()
		if attempt >= 12 || !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return err
		}
		// A terminated process or a file scanner can briefly hold the image.
		time.Sleep(125 * time.Millisecond)
	}
}

func hideConsole(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
}
