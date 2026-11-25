package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

func apiServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
}

func (s *server) serveAPI(ctx context.Context) error {
	servers := []*http.Server{apiServer(s.cfg.Listen, s.handler())}
	if s.cfg.PublicListen != "" {
		servers = append(servers, apiServer(s.cfg.PublicListen, s.publicHandler()))
	}
	if s.cfg.CertFile != "" {
		certificate, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("load API TLS certificate: %w", err)
		}
		for _, api := range servers {
			api.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certificate}}
		}
	}

	// Bind every address before any handler starts serving.
	listeners := make([]net.Listener, 0, len(servers))
	for _, api := range servers {
		var config net.ListenConfig
		listener, err := config.Listen(ctx, "tcp", api.Addr)
		if err != nil {
			return err
		}
		defer listener.Close()
		listeners = append(listeners, listener)
	}

	running, cancel := context.WithCancel(ctx)
	defer cancel()
	s.core.supervise(running, &s.write)
	results := make(chan error, len(servers))
	for i, api := range servers {
		go func() {
			listener := listeners[i]
			log.Printf("HomeProxy API listening on %s", listener.Addr())
			if api.TLSConfig != nil {
				results <- api.ServeTLS(listener, "", "")
			} else {
				results <- api.Serve(listener)
			}
		}()
	}

	var serveErr error
	remaining := len(servers)
	select {
	case <-ctx.Done():
	case serveErr = <-results:
		remaining--
	}
	cancel()
	shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	var stopping sync.WaitGroup
	for _, api := range servers {
		stopping.Go(func() {
			if err := api.Shutdown(shutdown); err != nil {
				api.Close()
			}
		})
	}
	stopping.Wait()
	for range remaining {
		err := <-results
		if serveErr == nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		return nil
	}
	return serveErr
}
