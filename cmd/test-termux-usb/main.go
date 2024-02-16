package main

import (
	"github.com/google/uuid"
	"log"
	"net"
	"os/exec"
	"strings"
)

func makeSocket() (net.Listener, *uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, nil, err
	}

	listener, err := net.Listen("unix", "@"+id.String())
	if err != nil {
		return nil, nil, err
	}
	return listener, &id, nil
}

func termuxApiCall(inputAddr string, outputAddr string) {
	cmd := exec.Command(
		"/data/data/com.termux/files/usr/bin/am",
		"broadcast",
		"--user",
		"0",
		"-n",
		"com.termux.api/.TermuxApiReceiver",
		"--es", "socket_input", outputAddr,
		"--es", "socket_output", inputAddr,
		"--es", "api_method", "Usb", "-a", "list",
	)
	var output strings.Builder
	cmd.Stdout = &output
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(output.String())
	log.Println(stderr.String())
}

func main() {
	// prepare input/output unix sockets
	input, inputId, err := makeSocket()
	if err != nil {
		log.Fatalln(err)
	}

	_, outputId, err := makeSocket()
	if err != nil {
		log.Fatalln(err)
	}

	termuxApiCall(inputId.String(), outputId.String())
	log.Println(inputId, err)
	conn, err := input.Accept()
	if err != nil {
		log.Fatalln(err)
	}

    log.Println("accepted")

	buffer := make([]byte, 1024)
	for {
        len, err := conn.Read(buffer)
        if len == 0 || err != nil {
            break
        }
        log.Println(string(buffer[:len]))
	}

	// defer l.Close()
}
