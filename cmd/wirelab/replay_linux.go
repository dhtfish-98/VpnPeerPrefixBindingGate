//go:build linux

// Copyright (c) 2026 dhtfish98. MIT License.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// replay duplicates an observed outgoing encrypted transport frame on an
// isolated veth link. It cannot see or alter the WireGuard plaintext.
func replay(args []string) {
	f := flag.NewFlagSet("replay", flag.ExitOnError)
	ifname := f.String("iface", "p1u", "peer underlay interface")
	seconds := f.Int("seconds", 6, "capture interval")
	f.Parse(args)
	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		fatal(err.Error())
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(3)))
	if err != nil {
		fatal(err.Error())
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Ifindex: iface.Index, Protocol: htons(3)}); err != nil {
		fatal(err.Error())
	}
	deadline := time.Now().Add(time.Duration(*seconds) * time.Second)
	fmt.Printf("REPLAY_READY iface=%s\n", *ifname)
	frame := make([]byte, 65535)
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 1})
		n, from, err := syscall.Recvfrom(fd, frame, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			fatal(err.Error())
		}
		link, ok := from.(*syscall.SockaddrLinklayer)
		if !ok || link.Pkttype != 4 || n < 14+20+8+33 { // 4 is PACKET_OUTGOING.
			continue
		}
		if frame[12] != 0x08 || frame[13] != 0x00 || frame[14]>>4 != 4 {
			continue
		}
		ihl := int(frame[14]&0x0f) * 4
		udp := 14 + ihl
		if ihl < 20 || udp+8+33 > n || frame[14+9] != 17 {
			continue
		}
		if binary.BigEndian.Uint16(frame[udp+2:udp+4]) != 51820 {
			continue
		}
		payload := frame[udp+8 : n]
		if binary.LittleEndian.Uint32(payload[:4]) != 4 {
			continue
		}
		copyFrame := append([]byte(nil), frame[:n]...)
		hash := sha256.Sum256(copyFrame)
		counter := binary.LittleEndian.Uint64(payload[8:16])
		time.Sleep(50 * time.Millisecond)
		to := &syscall.SockaddrLinklayer{Ifindex: iface.Index, Protocol: htons(0x0800), Halen: 6}
		copy(to.Addr[:], copyFrame[:6])
		if err := syscall.Sendto(fd, copyFrame, 0, to); err != nil {
			fatal(err.Error())
		}
		fmt.Printf("REPLAY_IDENTICAL=PASS sha256=%x counter=%d frame_bytes=%d\n", hash, counter, len(copyFrame))
		return
	}
	fmt.Println("REPLAY_IDENTICAL=FAIL no outgoing transport data")
	os.Exit(1)
}
