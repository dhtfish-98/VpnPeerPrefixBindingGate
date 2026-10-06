//go:build !linux

// Copyright (c) 2026 dhtfish98. MIT License.
package main

func replay(_ []string) { fatal("replay requires Linux AF_PACKET") }
