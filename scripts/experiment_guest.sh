#!/bin/sh
# Copyright (c) 2026 dhtfish98. MIT License.
set -eu
umask 077
BB=${LAB_BUSYBOX:-/usr/bin/busybox}
WG=${LAB_WG:-/usr/bin/wg}
NS=${LAB_NSENTER:-"$BB nsenter"}
UNSHARE=${LAB_UNSHARE:-"$BB unshare"}
IP=${LAB_IP:-/usr/bin/ip}
LAB=${LAB_WIRELAB:-/usr/bin/wirelab}

$BB mkdir -p /proc /sys
$BB mount -t proc proc /proc 2>/dev/null || true
$BB mount -t sysfs sysfs /sys 2>/dev/null || true
$BB mkdir -p /tmp
modprobe wireguard
modprobe veth
modprobe tun
$BB mkdir -p /dev/net
[ -c /dev/net/tun ] || $BB mknod /dev/net/tun c 10 200

$UNSHARE -n $BB sleep 120 > /tmp/ns1.out 2>&1 &
P1=$!
$UNSHARE -n $BB sleep 120 > /tmp/ns2.out 2>&1 &
P2=$!
$BB sleep 1
printf 'PIDS=%s,%s\n' "$P1" "$P2"
$BB cat /tmp/ns1.out /tmp/ns2.out
NS0=$($BB readlink /proc/self/ns/net)
NS1=$($BB readlink "/proc/$P1/ns/net")
NS2=$($BB readlink "/proc/$P2/ns/net")
printf 'NETNS_ROOT=%s NETNS_PEER1=%s NETNS_PEER2=%s\n' "$NS0" "$NS1" "$NS2"
if [ "$NS0" = "$NS1" ] || [ "$NS0" = "$NS2" ] || [ "$NS1" = "$NS2" ]; then
  echo 'NETNS_DISTINCT=FAIL'
  exit 1
fi
echo 'NETNS_DISTINCT=PASS'

$IP link add s1 type veth peer name p1u
$IP link add s2 type veth peer name p2u
$IP link set p1u netns "$P1"
$IP link set p2u netns "$P2"
$IP addr add 192.0.2.1/24 dev s1
$IP addr add 198.51.100.1/24 dev s2
$IP link set s1 up
$IP link set s2 up
$NS -t "$P1" -n $IP addr add 192.0.2.2/24 dev p1u
$NS -t "$P1" -n $IP link set p1u up
$NS -t "$P1" -n $IP link set lo up
$NS -t "$P2" -n $IP addr add 198.51.100.2/24 dev p2u
$NS -t "$P2" -n $IP link set p2u up
$NS -t "$P2" -n $IP link set lo up

$IP link add wg0 type wireguard
$NS -t "$P1" -n $IP link add wg1 type wireguard
$NS -t "$P2" -n $IP link add wg2 type wireguard

$WG genkey > /tmp/server.key
$WG genkey > /tmp/peer1.key
$WG genkey > /tmp/peer2.key
$WG pubkey < /tmp/server.key > /tmp/server.pub
$WG pubkey < /tmp/peer1.key > /tmp/peer1.pub
$WG pubkey < /tmp/peer2.key > /tmp/peer2.pub
SPUB=$($BB cat /tmp/server.pub)
P1PUB=$($BB cat /tmp/peer1.pub)
P2PUB=$($BB cat /tmp/peer2.pub)

$WG set wg0 private-key /tmp/server.key listen-port 51820 peer "$P1PUB" allowed-ips 10.0.1.2/32 peer "$P2PUB" allowed-ips 10.0.2.2/32
$NS -t "$P1" -n $WG set wg1 private-key /tmp/peer1.key listen-port 51831 peer "$SPUB" allowed-ips 10.0.0.1/32 endpoint 192.0.2.1:51820
$NS -t "$P2" -n $WG set wg2 private-key /tmp/peer2.key listen-port 51832 peer "$SPUB" allowed-ips 10.0.0.1/32 endpoint 198.51.100.1:51820
$IP addr add 10.0.0.1/24 dev wg0
$IP link set wg0 up
$IP route add 10.0.1.2/32 dev wg0
$IP route add 10.0.2.2/32 dev wg0
$NS -t "$P1" -n $IP addr add 10.0.1.2/32 dev wg1
$NS -t "$P1" -n $IP link set wg1 up
$NS -t "$P1" -n $IP route add 10.0.0.1/32 dev wg1
$NS -t "$P2" -n $IP addr add 10.0.2.2/32 dev wg2
$NS -t "$P2" -n $IP link set wg2 up
$NS -t "$P2" -n $IP route add 10.0.0.1/32 dev wg2

printf 'WG_CONFIG=PASS\n'
$WG show wg0
if $NS -t "$P1" -n $BB ping -c 1 -W 2 10.0.0.1; then echo 'PEER1_PING=PASS'; else echo 'PEER1_PING=FAIL'; fi
if $NS -t "$P2" -n $BB ping -c 1 -W 2 10.0.0.1; then echo 'PEER2_PING=PASS'; else echo 'PEER2_PING=FAIL'; fi

$NS -t "$P1" -n $LAB replay -iface p1u -seconds 6 > /tmp/replay.log 2>&1 &
REPLAY=$!
$LAB listen -seconds 7 > /tmp/receiver.log 2>&1 &
RECEIVER=$!
$BB sleep 1
$NS -t "$P1" -n $LAB send -src 10.0.1.2 -payload P1_ALLOWED
$NS -t "$P2" -n $LAB send -src 10.0.2.2 -payload P2_ALLOWED
$NS -t "$P1" -n $IP addr add 10.0.2.2/32 dev wg1
$NS -t "$P1" -n $LAB send -src 10.0.2.2 -payload P1_SPOOF
if wait "$REPLAY"; then echo 'REPLAY_EXIT=PASS'; else echo 'REPLAY_EXIT=FAIL'; fi
$NS -t "$P1" -n $LAB send -src 10.0.1.2 -payload P1_AFTER
$NS -t "$P2" -n $LAB send -src 10.0.2.2 -payload P2_AFTER
if wait "$RECEIVER"; then echo 'RECEIVER_EXIT=PASS'; else echo 'RECEIVER_EXIT=FAIL'; fi
$BB cat /tmp/receiver.log
$BB cat /tmp/replay.log

$LAB weak-gateway -seconds 5 > /tmp/weak-gateway.log 2>&1 &
WEAK_GATEWAY=$!
$BB sleep 1
$IP link set weak0 up
$LAB listen -mode weak -addr 10.0.0.1:55001 -seconds 4 > /tmp/weak-receiver.log 2>&1 &
WEAK_RECEIVER=$!
$BB sleep 1
$NS -t "$P1" -n $LAB weak-send -src 10.0.2.2 -payload WEAK_SPOOF
if wait "$WEAK_RECEIVER"; then echo 'WEAK_RECEIVER_EXIT=PASS'; else echo 'WEAK_RECEIVER_EXIT=FAIL'; fi
if wait "$WEAK_GATEWAY"; then echo 'WEAK_GATEWAY_EXIT=PASS'; else echo 'WEAK_GATEWAY_EXIT=FAIL'; fi
$BB cat /tmp/weak-receiver.log
$BB cat /tmp/weak-gateway.log

$LAB genkey -out /tmp/guard1.key
$LAB genkey -out /tmp/guard2.key
$LAB guard-gateway -key1 /tmp/guard1.key -key2 /tmp/guard2.key -seconds 8 > /tmp/guard-gateway.log 2>&1 &
GUARD_GATEWAY=$!
$BB sleep 1
$IP link set guard0 up
$LAB listen -mode guard -addr 10.0.0.1:55002 -seconds 7 > /tmp/guard-receiver.log 2>&1 &
GUARD_RECEIVER=$!
$BB sleep 1
$NS -t "$P1" -n $LAB guard-send -peer 1 -key-file /tmp/guard1.key -counter 1 -src 10.0.1.2 -payload G1_ALLOWED
$NS -t "$P2" -n $LAB guard-send -peer 2 -key-file /tmp/guard2.key -counter 1 -src 10.0.2.2 -payload G2_ALLOWED
$NS -t "$P1" -n $LAB guard-send -peer 1 -key-file /tmp/guard1.key -counter 2 -src 10.0.2.2 -payload G1_SPOOF
$NS -t "$P1" -n $LAB guard-send -peer 1 -key-file /tmp/guard1.key -counter 1 -src 10.0.1.2 -payload G1_ALLOWED
$NS -t "$P1" -n $LAB guard-send -peer 1 -key-file /tmp/guard1.key -counter 2 -src 10.0.1.2 -payload G1_AFTER
$NS -t "$P2" -n $LAB guard-send -peer 2 -key-file /tmp/guard2.key -counter 2 -src 10.0.2.2 -payload G2_AFTER
if wait "$GUARD_RECEIVER"; then echo 'GUARD_RECEIVER_EXIT=PASS'; else echo 'GUARD_RECEIVER_EXIT=FAIL'; fi
if wait "$GUARD_GATEWAY"; then echo 'GUARD_GATEWAY_EXIT=PASS'; else echo 'GUARD_GATEWAY_EXIT=FAIL'; fi
$BB cat /tmp/guard-receiver.log
$BB cat /tmp/guard-gateway.log
$IP -s link show wg0
echo 'EXPERIMENT_DONE'
