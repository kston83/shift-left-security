// Secure counterpart of insecure.go: must produce no findings.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	exec.Command("ping", "-c", "1", "localhost").Run()
	sum := sha256.Sum256([]byte("data"))
	w.Write(sum[:])
}

func server() *http.Server {
	return &http.Server{
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
}
