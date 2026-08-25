package main

import "net/http"

func advisories() (*http.Response, error) {
	return http.Get("https://api.osv.dev/v1/query")
}
