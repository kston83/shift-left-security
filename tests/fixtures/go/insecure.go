// Intentionally vulnerable test data for slsec-sast. Do not use.
package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"net/http"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Cmd{Path: host}
	cmd.Run()
	w.Write([]byte(md5.New().Sum(nil)))
	_ = sha1.New()
}

func server() *http.Server {
	return &http.Server{
		TLSConfig: &tls.Config{
			CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA},
		},
	}
}
