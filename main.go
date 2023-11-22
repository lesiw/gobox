package main

import (
	"fmt"
	"os"
	"path/filepath"

	gobox "lesiw.io/gobox/apps"
)

var (
	apps = map[string]func([]string, *gobox.IOs) int{
		"awk":      gobox.Awk,
		"basename": gobox.Basename,
		"false":    gobox.False,
		"true":     gobox.True,
	}
	stdios = &gobox.IOs{
		In:  os.Stdin,
		Out: os.Stdout,
		Err: os.Stderr,
	}
)

func main() {
	os.Exit(Exec(os.Args, stdios))
}

func Exec(argv []string, ios *gobox.IOs) int {
	argv[0] = filepath.Base(argv[0])

	if argv[0] == "gobox" {
		if len(argv) < 2 {
			fmt.Fprintln(ios.Err, "Usage: gobox [command]")
			fmt.Fprintln(ios.Err, "Available commands:")
			for app := range apps {
				fmt.Fprintln(ios.Err, app)
			}
			return 1
		}
		argv = argv[1:]
	}

	app := argv[0]
	appFunc, ok := apps[app]
	if !ok {
		fmt.Printf("Unknown app: %s\n", app)
		return 1
	}

	return appFunc(argv[1:], ios)
}
