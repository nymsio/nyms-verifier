package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/mail"
	"os"
)

var senderArg = flag.String("s", "", "sender address")
var configArg = flag.String("f", "", "config file path")
var debugArg = flag.Bool("d", false, "don't transmit response message, just dump it to stdout")

func main() {
	config := initialize()
	rawMail := readMessage()
	sender := getSenderAddress()
	err := processMail(rawMail, sender, config)
	if err != nil {
		fatal("Error processing message: %v", err)
	}
	os.Exit(0)
}

func initialize() *Config {
	flag.Parse()
	config, err := loadConfig(*configArg)
	if err != nil {
		fatal("Failed to load config file: %v", err)
	}
	setupLogging(config.LogPath)
	return config
}

func readMessage() []byte {
	msg, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fatal("Error reading input message from stdin: %v", err)
	}
	return msg
}

func getSenderAddress() *mail.Address {
	sender := *senderArg
	if sender == "" {
		sender := os.Getenv("SENDER")
		if sender == "" {
			fatal("No sender address specified with -s argument or $SENDER environment variable")
		}
	}
	addr, err := mail.ParseAddress(sender)
	if err != nil {
		fatal("Failed to parse sender address '%s': %v", sender, err)
	}
	return addr
}

func fatal(format string, args ...interface{}) {
	if logger != nil {
		logger.Error(format, args...)
	} else {
		fmt.Fprintf(os.Stderr, format, args...)
	}
	// lie and report successful completion to avoid bouncing messages
	os.Exit(0)
}
