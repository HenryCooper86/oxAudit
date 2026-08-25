package main

import "net/http"

// Deliberately NOT reported: a caller-supplied URL is this helper's API.
func fetchAdvisory(target string) (*http.Response, error) {
	return http.Get(target)
}
