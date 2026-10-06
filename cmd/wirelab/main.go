// Copyright (c) 2026 dhtfish98. MIT License.
// Isolated WireGuard packet-delivery experiment helper; no upstream code copied.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"vpnpeerprefixbinding/guard"
)

func main() {
	if len(os.Args) < 2 {
		fatal("mode required: listen, send, replay, weak-gateway, weak-send, guard-gateway, guard-send, or genkey")
	}
	switch os.Args[1] {
	case "listen":
		listen(os.Args[2:])
	case "send":
		send(os.Args[2:])
	case "replay":
		replay(os.Args[2:])
	case "weak-gateway":
		weakGateway(os.Args[2:])
	case "weak-send":
		weakSend(os.Args[2:])
	case "guard-gateway":
		guardGateway(os.Args[2:])
	case "guard-send":
		guardSend(os.Args[2:])
	case "genkey":
		genkey(os.Args[2:])
	default:
		fatal("unknown mode")
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "ERROR:", msg)
	os.Exit(1)
}

func udpAddress(s string) *net.UDPAddr {
	a, err := net.ResolveUDPAddr("udp4", s)
	if err != nil {
		fatal(err.Error())
	}
	return a
}

func checksum(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p[:2]))
		p = p[2:]
	}
	if len(p) != 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func makeInner(src, dst string, port uint16, payload string) []byte {
	srcIP, dstIP := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	if srcIP == nil || dstIP == nil || len(payload) > 65000 {
		fatal("invalid inner IPv4 address or payload")
	}
	p := make([]byte, 20+8+len(payload))
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], 0x1234)
	copy(p[12:16], srcIP)
	copy(p[16:20], dstIP)
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], port)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	copy(p[28:], payload)
	return p
}

func openTun(name string) *os.File {
	tun, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		fatal(err.Error())
	}
	var ifreq struct {
		Name  [16]byte
		Flags uint16
		Pad   [22]byte
	}
	if len(name) > 15 {
		fatal("TUN name too long")
	}
	copy(ifreq.Name[:], name)
	ifreq.Flags = 1 | 0x1000 // IFF_TUN | IFF_NO_PI.
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tun.Fd(), uintptr(0x400454ca), uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		fatal(errno.Error())
	}
	return tun
}

func readKey(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		fatal(err.Error())
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != 32 {
		fatal("expected a base64-encoded 32-byte key")
	}
	return key
}

func genkey(args []string) {
	f := flag.NewFlagSet("genkey", flag.ExitOnError)
	out := f.String("out", "", "key output file")
	f.Parse(args)
	if *out == "" {
		fatal("out required")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fatal(err.Error())
	}
	if err := os.WriteFile(*out, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0600); err != nil {
		fatal(err.Error())
	}
	fmt.Println("GUARD_KEY_CREATED=PASS")
}

func guardSend(args []string) {
	f := flag.NewFlagSet("guard-send", flag.ExitOnError)
	id := f.Int("peer", 0, "authenticated lab peer ID")
	keyFile := f.String("key-file", "", "separate lab HMAC key")
	counter := f.Uint64("counter", 0, "packet counter")
	src := f.String("src", "", "claimed inner IPv4 source")
	payload := f.String("payload", "", "inner UDP marker")
	f.Parse(args)
	if (*id != 1 && *id != 2) || *keyFile == "" || *src == "" || *payload == "" {
		fatal("peer 1/2, key-file, src, and payload required")
	}
	p, err := guard.Seal(byte(*id), readKey(*keyFile), *counter, makeInner(*src, "10.0.0.1", 55002, *payload))
	if err != nil {
		fatal(err.Error())
	}
	underlay := "192.0.2.2:0"
	target := "192.0.2.1:60001"
	if *id == 2 {
		underlay = "198.51.100.2:0"
		target = "198.51.100.1:60001"
	}
	c, err := net.DialUDP("udp4", udpAddress(underlay), udpAddress(target))
	if err != nil {
		fatal(err.Error())
	}
	defer c.Close()
	if _, err := c.Write(p); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("GUARD_SENT peer=%d counter=%d claim=%s payload=%s\n", *id, *counter, *src, *payload)
}

func guardGateway(args []string) {
	f := flag.NewFlagSet("guard-gateway", flag.ExitOnError)
	key1 := f.String("key1", "", "peer 1 key file")
	key2 := f.String("key2", "", "peer 2 key file")
	seconds := f.Int("seconds", 8, "capture interval")
	f.Parse(args)
	if *key1 == "" || *key2 == "" {
		fatal("key1 and key2 required")
	}
	g, err := guard.New([]guard.Policy{
		{ID: 1, Key: readKey(*key1), Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.1.2/32")}},
		{ID: 2, Key: readKey(*key2), Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.2.2/32")}},
	})
	if err != nil {
		fatal(err.Error())
	}
	tun := openTun("guard0")
	defer tun.Close()
	c, err := net.ListenUDP("udp4", udpAddress("0.0.0.0:60001"))
	if err != nil {
		fatal(err.Error())
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Duration(*seconds) * time.Second))
	fmt.Println("GUARD_GATEWAY_READY iface=guard0 port=60001")
	counts := map[string]int{}
	buf := make([]byte, 65535)
	for i := 0; i < 6; i++ {
		n, sender, err := c.ReadFromUDP(buf)
		if err != nil {
			fatal(err.Error())
		}
		d := g.Check(buf[:n])
		counts[d.Reason]++
		fmt.Printf("GUARD_DECISION peer=%d counter=%d claimed_source=%s reason=%s underlay=%s\n", d.PeerID, d.Counter, d.Source, d.Reason, sender.IP)
		if d.Allowed {
			if _, err := tun.Write(d.Packet); err != nil {
				fatal(err.Error())
			}
		}
	}
	if counts["allowed"] == 4 && counts["source_prefix"] == 1 && counts["replay"] == 1 {
		fmt.Println("GUARD_MATRIX=PASS")
	} else {
		fmt.Printf("GUARD_MATRIX=FAIL counts=%v\n", counts)
		os.Exit(1)
	}
	time.Sleep(time.Second)
}

// weakSend represents a deliberately insecure peer that claims any inner
// source in an IPv4 packet placed into a simple UDP envelope.
func weakSend(args []string) {
	f := flag.NewFlagSet("weak-send", flag.ExitOnError)
	src := f.String("src", "10.0.2.2", "claimed inner IPv4 source")
	dst := f.String("dst", "10.0.0.1", "inner IPv4 destination")
	payload := f.String("payload", "WEAK_SPOOF", "inner UDP marker")
	f.Parse(args)
	srcIP, dstIP := net.ParseIP(*src).To4(), net.ParseIP(*dst).To4()
	if srcIP == nil || dstIP == nil {
		fatal("IPv4 addresses required")
	}
	p := make([]byte, 20+8+len(*payload))
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], 0x1234)
	copy(p[12:16], srcIP)
	copy(p[16:20], dstIP)
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	binary.BigEndian.PutUint16(p[20:22], 40000)
	binary.BigEndian.PutUint16(p[22:24], 55001)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(*payload)))
	copy(p[28:], *payload)
	c, err := net.DialUDP("udp4", udpAddress("192.0.2.2:0"), udpAddress("192.0.2.1:60000"))
	if err != nil {
		fatal(err.Error())
	}
	defer c.Close()
	if _, err := c.Write(p); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("WEAK_SENT underlay=192.0.2.2 claimed_inner_source=%s payload=%s\n", *src, *payload)
}

// weakGateway intentionally omits peer-to-inner-source binding. The unsafe
// behavior is scoped to the disposable VM as an explanatory baseline.
func weakGateway(args []string) {
	f := flag.NewFlagSet("weak-gateway", flag.ExitOnError)
	seconds := f.Int("seconds", 5, "wait for weak packet")
	f.Parse(args)
	tun, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		fatal(err.Error())
	}
	defer tun.Close()
	var ifreq struct {
		Name  [16]byte
		Flags uint16
		Pad   [22]byte
	}
	copy(ifreq.Name[:], "weak0")
	ifreq.Flags = 1 | 0x1000 // IFF_TUN | IFF_NO_PI.
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tun.Fd(), uintptr(0x400454ca), uintptr(unsafe.Pointer(&ifreq)))
	if errno != 0 {
		fatal(errno.Error())
	}
	c, err := net.ListenUDP("udp4", udpAddress("192.0.2.1:60000"))
	if err != nil {
		fatal(err.Error())
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Duration(*seconds) * time.Second))
	fmt.Println("WEAK_GATEWAY_READY iface=weak0 port=60000")
	buf := make([]byte, 65535)
	n, src, err := c.ReadFromUDP(buf)
	if err != nil {
		fatal(err.Error())
	}
	if !src.IP.Equal(net.ParseIP("192.0.2.2")) || n < 28 || buf[0]>>4 != 4 {
		fatal("unexpected weak packet")
	}
	if _, err := tun.Write(buf[:n]); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("WEAK_UNBOUND_FORWARD=PASS underlay_peer=%s claimed_inner_source=%s bytes=%d\n", src.IP, net.IP(buf[12:16]), n)
	time.Sleep(time.Second)
}

func listen(args []string) {
	f := flag.NewFlagSet("listen", flag.ExitOnError)
	addr := f.String("addr", "10.0.0.1:55000", "inner UDP address")
	seconds := f.Int("seconds", 8, "capture interval")
	mode := f.String("mode", "secure", "secure or weak expected deliveries")
	f.Parse(args)
	c, err := net.ListenUDP("udp4", udpAddress(*addr))
	if err != nil {
		fatal(err.Error())
	}
	defer c.Close()
	if err := c.SetReadDeadline(time.Now().Add(time.Duration(*seconds) * time.Second)); err != nil {
		fatal(err.Error())
	}
	fmt.Printf("LISTEN_READY addr=%s\n", c.LocalAddr())
	counts := map[string]int{}
	sources := map[string]string{}
	buf := make([]byte, 2048)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			break
		}
		if err != nil {
			fatal(err.Error())
		}
		payload := string(buf[:n])
		counts[payload]++
		sources[payload] = src.IP.String()
		fmt.Printf("DELIVERY source=%s payload=%s count=%d\n", src.IP, payload, counts[payload])
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Printf("COUNT payload=%s value=%d\n", key, counts[key])
	}
	if *mode == "weak" {
		if counts["WEAK_SPOOF"] == 1 && sources["WEAK_SPOOF"] == "10.0.2.2" {
			fmt.Println("WEAK_DELIVERY=PASS")
			return
		}
		fmt.Println("WEAK_DELIVERY=FAIL")
		os.Exit(1)
	}
	if *mode == "guard" {
		if counts["G1_ALLOWED"] == 1 && sources["G1_ALLOWED"] == "10.0.1.2" && counts["G2_ALLOWED"] == 1 && sources["G2_ALLOWED"] == "10.0.2.2" && counts["G1_SPOOF"] == 0 && counts["G1_AFTER"] == 1 && sources["G1_AFTER"] == "10.0.1.2" && counts["G2_AFTER"] == 1 && sources["G2_AFTER"] == "10.0.2.2" {
			fmt.Println("GUARD_DELIVERY=PASS")
			return
		}
		fmt.Println("GUARD_DELIVERY=FAIL")
		os.Exit(1)
	}
	if counts["P1_ALLOWED"] == 1 && sources["P1_ALLOWED"] == "10.0.1.2" && counts["P2_ALLOWED"] == 1 && sources["P2_ALLOWED"] == "10.0.2.2" && counts["P1_SPOOF"] == 0 && counts["P1_AFTER"] == 1 && sources["P1_AFTER"] == "10.0.1.2" && counts["P2_AFTER"] == 1 && sources["P2_AFTER"] == "10.0.2.2" {
		fmt.Println("DELIVERY_MATRIX=PASS")
	} else {
		fmt.Println("DELIVERY_MATRIX=FAIL")
		os.Exit(1)
	}
}

func send(args []string) {
	f := flag.NewFlagSet("send", flag.ExitOnError)
	src := f.String("src", "", "required inner source IP")
	dst := f.String("dst", "10.0.0.1:55000", "inner UDP target")
	payload := f.String("payload", "", "test marker")
	f.Parse(args)
	if *src == "" || *payload == "" {
		fatal("src and payload required")
	}
	c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(*src)}, udpAddress(*dst))
	if err != nil {
		fatal(err.Error())
	}
	defer c.Close()
	n, err := c.Write([]byte(*payload))
	if err != nil {
		fatal(err.Error())
	}
	fmt.Printf("SENT source=%s payload=%s bytes=%d\n", *src, *payload, n)
}
