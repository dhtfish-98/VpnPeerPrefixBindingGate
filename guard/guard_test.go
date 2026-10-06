// Copyright (c) 2026 dhtfish98. MIT License.
package guard

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func packet(source string) []byte {
	p := make([]byte, 20+8+5)
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	src := netip.MustParseAddr(source).As4()
	dst := netip.MustParseAddr("10.0.0.1").As4()
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[10:12], ipv4Checksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], 55000)
	binary.BigEndian.PutUint16(p[24:26], 13)
	copy(p[28:], "hello")
	return p
}

func testGate(t *testing.T) (*Gate, []byte, []byte) {
	t.Helper()
	k1, k2 := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	g, err := New([]Policy{
		{ID: 1, Key: k1, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.1.2/32")}},
		{ID: 2, Key: k2, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.2.2/32")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, k1, k2
}

func check(t *testing.T, g *Gate, id byte, key []byte, counter uint64, source, reason string) {
	t.Helper()
	f, err := Seal(id, key, counter, packet(source))
	if err != nil {
		t.Fatal(err)
	}
	d := g.Check(f)
	if d.Reason != reason || d.Allowed != (reason == "allowed") {
		t.Fatalf("peer %d counter %d source %s: got %#v, want %s", id, counter, source, d, reason)
	}
	if d.Allowed && (len(d.Packet) == 0 || d.Source.String() != source) {
		t.Fatalf("accepted frame did not retain validated source/payload: %#v", d)
	}
}

func TestPeerPrefixAndReplay(t *testing.T) {
	g, k1, k2 := testGate(t)
	check(t, g, 1, k1, 1, "10.0.1.2", "allowed")
	check(t, g, 2, k2, 1, "10.0.2.2", "allowed")
	check(t, g, 1, k1, 2, "10.0.2.2", "source_prefix")
	check(t, g, 1, k1, 1, "10.0.1.2", "replay")
	check(t, g, 1, k1, 2, "10.0.1.2", "allowed") // rejected spoof did not consume counter
	check(t, g, 2, k2, 2, "10.0.2.2", "allowed")
	check(t, g, 1, k1, 100, "10.0.1.2", "allowed")
	check(t, g, 1, k1, 2, "10.0.1.2", "replay") // outside 64-counter window
}

func TestAuthenticationAndMalformedFailClosed(t *testing.T) {
	g, k1, _ := testGate(t)
	frame, err := Seal(1, k1, 1, packet("10.0.1.2"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), frame...)
	tampered[20] ^= 1
	if got := g.Check(tampered).Reason; got != "authentication" {
		t.Fatalf("tampered frame: %s", got)
	}
	unknown := append([]byte(nil), frame...)
	unknown[1] = 99
	if got := g.Check(unknown).Reason; got != "unknown_peer" {
		t.Fatalf("unknown peer: %s", got)
	}
	if got := g.Check(frame[:len(frame)-1]).Reason; got != "malformed" {
		t.Fatalf("truncated frame: %s", got)
	}
	badIP := packet("10.0.1.2")
	badIP[10] ^= 1
	sealed, err := Seal(1, k1, 1, badIP)
	if err != nil {
		t.Fatal(err)
	}
	if got := g.Check(sealed).Reason; got != "malformed_ipv4" {
		t.Fatalf("invalid IPv4 checksum: %s", got)
	}
	check(t, g, 1, k1, 1, "10.0.1.2", "allowed") // bad frames did not consume counter
}

func TestOverlappingAndNoncanonicalPrefixesRefused(t *testing.T) {
	key := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	other := []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	_, err := New([]Policy{
		{ID: 1, Key: key, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")}},
		{ID: 2, Key: other, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.1.2/32")}},
	})
	if err == nil {
		t.Fatal("overlapping peer ownership accepted")
	}
	_, err = New([]Policy{{ID: 1, Key: key, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.1.2/24")}}})
	if err == nil {
		t.Fatal("noncanonical prefix accepted")
	}
	_, err = New([]Policy{
		{ID: 1, Key: key, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.1.2/32")}},
		{ID: 2, Key: key, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.2.2/32")}},
	})
	if err == nil {
		t.Fatal("shared peer secret accepted")
	}
}
