package main

import "testing"

func TestMainBoots(t *testing.T) {
	// Just ensure it doesn't panic
	go main()
}
