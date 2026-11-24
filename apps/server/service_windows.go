package main

import (
	"context"
	"log"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
)

const serviceName = "HomeProxyServer"

type serviceHandler struct{ ctx context.Context }

func (h serviceHandler) Execute(args []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	statuses <- svc.Status{State: svc.StartPending}
	if len(args) > 1 && args[1] == "homeproxy-update" {
		if len(args) != 5 || strings.TrimPrefix(args[2], "v") != strings.TrimPrefix(releaseVersion, "v") ||
			args[3] != strconv.Itoa(apiVersion) || args[4] != strconv.Itoa(schemaVersion) {
			log.Print("service update rejected: incompatible release, API or database schema")
			return true, 2
		}
	}
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	status := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- status
	for {
		select {
		case err := <-done:
			if err != nil {
				log.Print(err)
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- status
			case svc.Stop, svc.Shutdown:
				status = svc.Status{State: svc.StopPending, WaitHint: uint32((15 * time.Second).Milliseconds())}
				statuses <- status
				cancel()
			}
		}
	}
}

func runPlatform(ctx context.Context) error {
	service, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if service {
		return svc.Run(serviceName, serviceHandler{ctx})
	}
	return run(ctx)
}
