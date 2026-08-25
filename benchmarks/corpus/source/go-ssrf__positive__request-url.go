package main

import "net/http"

func proxy(w http.ResponseWriter, r *http.Request) (*http.Response, error) {
	target := r.FormValue("target")
	return http.Get(target)
}
