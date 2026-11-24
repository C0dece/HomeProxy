//go:build admin_bundle

package main

import (
	"embed"
	"io/fs"
)

//go:embed admin-panel
var adminPanel embed.FS

func init() {
	var err error
	bundledAdmin, err = fs.Sub(adminPanel, "admin-panel")
	if err != nil {
		panic(err)
	}
}
