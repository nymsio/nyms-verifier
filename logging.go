package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/user"

	gl "github.com/op/go-logging"

	"path/filepath"
)

var logger *gl.Logger

const defaultLogPath = ".nyms/verify_log"

func setupLogging(logfile string) {
	out := getLogOutput(logfile)
	be := gl.NewLogBackend(out, "", log.Ltime)
	gl.SetBackend(be)
	logger = gl.MustGetLogger("verifier")
}

func getLogOutput(logfile string) io.Writer {
	if *debugArg {
		// If debug flag is enabled log to stderr
		return os.Stderr
	}
	f, err := openLogFile(logfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Logging to stderr, failed to open logfile: %v", err)
		return os.Stderr
	}
	return f
}

func openLogFile(logfile string) (io.Writer, error) {
	if logfile == "" {
		logfile = getDefaultLogPath()
	}
	dir := filepath.Dir(logfile)
	err := os.MkdirAll(dir, 0711)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(logfile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
}

func getDefaultLogPath() string {
	u, err := user.Current()
	if err != nil {
		panic(fmt.Sprintf("Failed to get current user information: %v", err))
	}
	return filepath.Join(u.HomeDir, defaultLogPath)
}
