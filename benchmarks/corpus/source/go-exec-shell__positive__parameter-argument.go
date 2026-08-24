package main

import "os/exec"

func run(userSupplied string) error {
	return exec.Command("sh", "-c", userSupplied).Run()
}
