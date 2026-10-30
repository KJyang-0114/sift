package main

import "net/http"

func handler(w http.ResponseWriter, token string) {
	// ruleid: sift.session-cookie-no-httponly-go
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Secure: true})
	// ok: sift.session-cookie-no-httponly-go
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Secure: true, HttpOnly: true})
}
