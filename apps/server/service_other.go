//go:build !windows

package main

import "context"

func runPlatform(ctx context.Context) error { return run(ctx) }
