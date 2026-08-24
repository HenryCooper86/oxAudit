package main

import "os/exec"

func listing() error {
	// Nothing here comes from outside the program.
	return exec.Command("sh", "-c", "ls -la").Run()
}
