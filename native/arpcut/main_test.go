package main

import (
	"net"
	"testing"
)

func TestHtons(t *testing.T) {
	if got := htons(0x0806); got != 0x0608 {
		t.Fatalf("htons(0x0806) = 0x%04x, want 0x0608", got)
	}
	if got := htons(0x0800); got != 0x0008 {
		t.Fatalf("htons(0x0800) = 0x%04x, want 0x0008", got)
	}
}

// arpBody must produce the exact 28-byte Ethernet/IPv4 ARP payload the kernel
// expects. A wrong offset here silently poisons nothing (or the wrong host), so
// pin the whole layout.
func TestArpBodyLayout(t *testing.T) {
	sMac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	tMac, _ := net.ParseMAC("11:22:33:44:55:66")
	sIP := net.ParseIP("192.168.1.2")
	tIP := net.ParseIP("192.168.1.1")

	b := arpBody(arpReply, sMac, sIP, tMac, tIP)
	if len(b) != 28 {
		t.Fatalf("len = %d, want 28", len(b))
	}
	// htype=1, ptype=0x0800, hlen=6, plen=4, oper=reply(2)
	want := []byte{0, 1, 0x08, 0x00, 6, 4, 0, 2}
	for i, w := range want {
		if b[i] != w {
			t.Fatalf("header byte %d = 0x%02x, want 0x%02x", i, b[i], w)
		}
	}
	if got := net.HardwareAddr(b[8:14]).String(); got != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("sender mac = %s", got)
	}
	if got := net.IP(b[14:18]).String(); got != "192.168.1.2" {
		t.Fatalf("sender ip = %s", got)
	}
	if got := net.HardwareAddr(b[18:24]).String(); got != "11:22:33:44:55:66" {
		t.Fatalf("target mac = %s", got)
	}
	if got := net.IP(b[24:28]).String(); got != "192.168.1.1" {
		t.Fatalf("target ip = %s", got)
	}
}

func TestArpBodyOpcode(t *testing.T) {
	m, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	ip := net.ParseIP("10.0.0.1")
	if arpBody(arpRequest, m, ip, m, ip)[7] != 1 {
		t.Fatal("request opcode should be 1")
	}
	if arpBody(arpReply, m, ip, m, ip)[7] != 2 {
		t.Fatal("reply opcode should be 2")
	}
}

func TestParseVictimsModes(t *testing.T) {
	vs := parseVictims([]string{
		"192.168.1.10@aa:bb:cc:dd:ee:01@v", // cut → victim only
		"192.168.1.11@aa:bb:cc:dd:ee:02@b", // throttle → both
		"192.168.1.12@aa:bb:cc:dd:ee:03",   // no mode → both (default)
	})
	if len(vs) != 3 {
		t.Fatalf("got %d victims, want 3", len(vs))
	}
	if vs[0].both {
		t.Error("mode v must be victim-only (both=false)")
	}
	if !vs[1].both {
		t.Error("mode b must be both")
	}
	if !vs[2].both {
		t.Error("absent mode must default to both")
	}
	if vs[0].ip.String() != "192.168.1.10" {
		t.Errorf("ip parsed wrong: %s", vs[0].ip)
	}
}

// A malformed target must be skipped, never fatal — one bad arg can't take down
// the whole cut.
func TestParseVictimsSkipsGarbage(t *testing.T) {
	vs := parseVictims([]string{
		"not-an-ip@aa:bb:cc:dd:ee:ff",
		"192.168.1.10@zz:zz",               // bad mac
		"192.168.1.10",                     // no mac
		"",                                 // empty
		"192.168.1.20@aa:bb:cc:dd:ee:20@v", // the one good entry
	})
	if len(vs) != 1 {
		t.Fatalf("got %d victims, want 1 (only the valid entry)", len(vs))
	}
	if vs[0].ip.String() != "192.168.1.20" || vs[0].both {
		t.Errorf("unexpected victim: %+v", vs[0])
	}
}

func TestParseVictimsEmpty(t *testing.T) {
	if got := parseVictims(nil); len(got) != 0 {
		t.Fatalf("nil args should yield 0 victims, got %d", len(got))
	}
}
