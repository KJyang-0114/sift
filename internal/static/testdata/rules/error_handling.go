package main

import "net/http"

func handler(w http.ResponseWriter, err error) {
	// ruleid: sift.error-stack-trace-leak
	http.Error(w, err.Error(), http.StatusInternalServerError)
	// ok: sift.error-stack-trace-leak
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func describe(err error) string {
	// ok: sift.error-stack-trace-leak
	return err.Error()
}
