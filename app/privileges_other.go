//go:build !linux

package main

// dropPrivileges is a no-op outside Linux (local development on Windows/macOS).
func dropPrivileges(string) error { return nil }
