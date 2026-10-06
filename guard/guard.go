// Copyright (c) 2026 dhtfish98. MIT License.
// This is an independent reference gate for the synthetic lab tunnel.
package guard

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
)

const (
	frameVersion = 1
	frameHeader  = 12 // version, peer ID, uint64 counter, uint16 packet length
	tagSize      = sha256.Size
	minIPv4      = 20
)

type Policy struct {
	ID       byte
	Key      []byte
	Prefixes []netip.Prefix
}

type peerState struct {
	key         []byte
	prefixes    []netip.Prefix
	initialized bool
	high        uint64
	seen        uint64
}

type Gate struct {
	mu    sync.Mutex
	peers map[byte]*peerState
}

type Decision struct {
	Allowed bool
	Reason  string
	PeerID  byte
	Counter uint64
	Source  netip.Addr
	Packet  []byte // populated only after all checks pass
}

func New(policies []Policy) (*Gate, error) {
	if len(policies) == 0 {
		return nil, errors.New("at least one peer is required")
	}
	g := &Gate{peers: make(map[byte]*peerState, len(policies))}
	var occupied []netip.Prefix
	for _, p := range policies {
		if len(p.Key) != 32 || len(p.Prefixes) == 0 {
			return nil, errors.New("each peer needs a 32-byte key and a source prefix")
		}
		if _, exists := g.peers[p.ID]; exists {
			return nil, errors.New("duplicate peer identity")
		}
		for _, earlier := range g.peers {
			if bytes.Equal(earlier.key, p.Key) {
				return nil, errors.New("peer keys must be distinct")
			}
		}
		state := &peerState{key: append([]byte(nil), p.Key...)}
		for _, prefix := range p.Prefixes {
			if !prefix.IsValid() || !prefix.Addr().Is4() || prefix != prefix.Masked() {
				return nil, errors.New("source prefix must be a canonical IPv4 prefix")
			}
			for _, earlier := range occupied {
				if earlier.Contains(prefix.Addr()) || prefix.Contains(earlier.Addr()) {
					return nil, errors.New("overlapping source prefixes")
				}
			}
			occupied = append(occupied, prefix)
			state.prefixes = append(state.prefixes, prefix)
		}
		g.peers[p.ID] = state
	}
	return g, nil
}

// Seal frames an already constructed IPv4 packet for the isolated lab tunnel.
// It is not WireGuard encryption and must not be used as a VPN protocol.
func Seal(id byte, key []byte, counter uint64, packet []byte) ([]byte, error) {
	if len(key) != 32 || len(packet) > 65535 || len(packet) < minIPv4 {
		return nil, errors.New("invalid key or IPv4 packet size")
	}
	frame := make([]byte, frameHeader+len(packet)+tagSize)
	frame[0], frame[1] = frameVersion, id
	binary.BigEndian.PutUint64(frame[2:10], counter)
	binary.BigEndian.PutUint16(frame[10:12], uint16(len(packet)))
	copy(frame[frameHeader:], packet)
	mac := hmac.New(sha256.New, key)
	mac.Write(frame[:len(frame)-tagSize])
	copy(frame[len(frame)-tagSize:], mac.Sum(nil))
	return frame, nil
}

func (g *Gate) Check(frame []byte) Decision {
	d := Decision{Reason: "malformed"}
	if len(frame) < frameHeader+minIPv4+tagSize || frame[0] != frameVersion {
		return d
	}
	d.PeerID = frame[1]
	d.Counter = binary.BigEndian.Uint64(frame[2:10])
	length := int(binary.BigEndian.Uint16(frame[10:12]))
	if length < minIPv4 || len(frame) != frameHeader+length+tagSize {
		return d
	}
	peer := g.peers[d.PeerID]
	if peer == nil {
		d.Reason = "unknown_peer"
		return d
	}
	mac := hmac.New(sha256.New, peer.key)
	mac.Write(frame[:len(frame)-tagSize])
	if !hmac.Equal(mac.Sum(nil), frame[len(frame)-tagSize:]) {
		d.Reason = "authentication"
		return d
	}
	packet := frame[frameHeader : frameHeader+length]
	src, ok := ipv4Source(packet)
	if !ok {
		d.Reason = "malformed_ipv4"
		return d
	}
	d.Source = src
	bound := false
	for _, prefix := range peer.prefixes {
		if prefix.Contains(src) {
			bound = true
			break
		}
	}
	if !bound {
		d.Reason = "source_prefix"
		return d
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !peer.acceptCounter(d.Counter) {
		d.Reason = "replay"
		return d
	}
	d.Allowed = true
	d.Reason = "allowed"
	d.Packet = append([]byte(nil), packet...)
	return d
}

func ipv4Source(packet []byte) (netip.Addr, bool) {
	if len(packet) < minIPv4 || packet[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	ihl := int(packet[0]&15) * 4
	if ihl < minIPv4 || ihl > len(packet) || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return netip.Addr{}, false
	}
	// Drop fragments; a fragment stream would require reassembly before policy.
	if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return netip.Addr{}, false
	}
	if ipv4Checksum(packet[:ihl]) != 0 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte(packet[12:16])), true
}

func ipv4Checksum(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p[:2]))
		p = p[2:]
	}
	if len(p) == 1 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (p *peerState) acceptCounter(counter uint64) bool {
	if !p.initialized {
		p.initialized, p.high, p.seen = true, counter, 1
		return true
	}
	if counter > p.high {
		shift := counter - p.high
		if shift >= 64 {
			p.seen = 1
		} else {
			p.seen = p.seen<<shift | 1
		}
		p.high = counter
		return true
	}
	delta := p.high - counter
	if delta >= 64 || p.seen&(uint64(1)<<delta) != 0 {
		return false
	}
	p.seen |= uint64(1) << delta
	return true
}
