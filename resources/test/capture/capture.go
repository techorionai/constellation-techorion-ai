// Package capture reads a pcap file of a network namespace and finds the
// outbound calls that are not in an allow list. It uses only outbound packets:
// a TCP SYN without ACK from a local address, and a UDP packet from a local
// address. It reads DNS queries to the Docker DNS server and records the query
// names. It never reports a pass for an empty, truncated, or malformed file.
package capture

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// DockerDNS is the address of the embedded DNS server of Docker.
var DockerDNS = netip.MustParseAddr("127.0.0.11")

// Allow is the allow list of an analysis.
type Allow struct {
	// Peers are the allowed destinations. An entry with port 0 allows all
	// ports of that address.
	Peers []netip.AddrPort
	// DNSNames are the allowed names in DNS queries. The comparison ignores
	// case and a dot at the end.
	DNSNames []string
}

// Result is the result of an analysis.
type Result struct {
	// Packets is the number of packets in the file.
	Packets int
	// Peers are all outbound peers that the file shows, without duplicates.
	Peers []netip.AddrPort
	// DNSNames are all DNS query names that the file shows, without duplicates.
	DNSNames []string
	// UnexpectedPeers are the peers that are not in the allow list.
	UnexpectedPeers []netip.AddrPort
	// UnexpectedDNSNames are the query names that are not in the allow list.
	UnexpectedDNSNames []string
}

// OK reports whether the result has no unexpected peer and no unexpected name.
func (r Result) OK() bool {
	return len(r.UnexpectedPeers) == 0 && len(r.UnexpectedDNSNames) == 0
}

// Analyze reads a pcap stream. The local addresses are the addresses of the
// network namespace. It returns an error for an empty, truncated, or malformed
// stream, and for a stream with no packets.
func Analyze(r io.Reader, local []netip.Addr, allow Allow) (Result, error) {
	var res Result
	rd, err := pcapgo.NewReader(r)
	if err != nil {
		return res, fmt.Errorf("capture: read pcap header: %w", err)
	}
	localSet := map[netip.Addr]bool{}
	for _, a := range local {
		localSet[a.Unmap()] = true
	}
	peers := map[netip.AddrPort]bool{}
	names := map[string]bool{}
	linkType := rd.LinkType()
	for {
		data, ci, err := rd.ReadPacketData()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return res, fmt.Errorf("capture: read packet %d: %w", res.Packets+1, err)
		}
		_ = ci
		res.Packets++
		pk := gopacket.NewPacket(data, linkType, gopacket.NoCopy)
		src, dst, ok := addresses(pk)
		if !ok {
			return res, fmt.Errorf("capture: packet %d has no IP layer", res.Packets)
		}
		if !localSet[src] {
			continue
		}
		if tcp, _ := pk.Layer(layers.LayerTypeTCP).(*layers.TCP); tcp != nil {
			if dst.Addr() == DockerDNS {
				for _, n := range dnsNamesTCP(tcp.Payload) {
					names[normalize(n)] = true
				}
				continue
			}
			if tcp.SYN && !tcp.ACK {
				if dst.Addr().IsLoopback() && src.IsLoopback() {
					continue
				}
				peers[netip.AddrPortFrom(dst.Addr(), uint16(tcp.DstPort))] = true
			}
			continue
		}
		if udp, _ := pk.Layer(layers.LayerTypeUDP).(*layers.UDP); udp != nil {
			if dst.Addr() == DockerDNS {
				for _, n := range dnsNames(udp.Payload) {
					names[normalize(n)] = true
				}
				continue
			}
			if dst.Addr().IsLoopback() && src.IsLoopback() {
				continue
			}
			peers[netip.AddrPortFrom(dst.Addr(), uint16(udp.DstPort))] = true
		}
	}
	if res.Packets == 0 {
		return res, errors.New("capture: the pcap file has no packets")
	}
	res.Peers = sortedPeers(peers)
	res.DNSNames = sortedKeys(names)
	for _, p := range res.Peers {
		if !allowedPeer(allow.Peers, p) {
			res.UnexpectedPeers = append(res.UnexpectedPeers, p)
		}
	}
	allowedNames := map[string]bool{}
	for _, n := range allow.DNSNames {
		allowedNames[normalize(n)] = true
	}
	for _, n := range res.DNSNames {
		if !allowedNames[n] {
			res.UnexpectedDNSNames = append(res.UnexpectedDNSNames, n)
		}
	}
	return res, nil
}

func addresses(pk gopacket.Packet) (src netip.Addr, dst netip.AddrPort, ok bool) {
	port := func() uint16 {
		if tcp, _ := pk.Layer(layers.LayerTypeTCP).(*layers.TCP); tcp != nil {
			return uint16(tcp.DstPort)
		}
		if udp, _ := pk.Layer(layers.LayerTypeUDP).(*layers.UDP); udp != nil {
			return uint16(udp.DstPort)
		}
		return 0
	}
	if ip4, _ := pk.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ip4 != nil {
		s, ok1 := netip.AddrFromSlice(ip4.SrcIP)
		d, ok2 := netip.AddrFromSlice(ip4.DstIP)
		if !ok1 || !ok2 {
			return src, dst, false
		}
		return s.Unmap(), netip.AddrPortFrom(d.Unmap(), port()), true
	}
	if ip6, _ := pk.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ip6 != nil {
		s, ok1 := netip.AddrFromSlice(ip6.SrcIP)
		d, ok2 := netip.AddrFromSlice(ip6.DstIP)
		if !ok1 || !ok2 {
			return src, dst, false
		}
		return s.Unmap(), netip.AddrPortFrom(d.Unmap(), port()), true
	}
	return src, dst, false
}

// dnsNames returns the query names of a DNS message. A message that does not
// decode gives no name.
func dnsNames(payload []byte) []string {
	var d layers.DNS
	if err := d.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return nil
	}
	var out []string
	for _, q := range d.Questions {
		out = append(out, string(q.Name))
	}
	return out
}

// dnsNamesTCP returns the query names of a DNS message with the 2-byte length
// prefix of DNS over TCP.
func dnsNamesTCP(payload []byte) []string {
	if len(payload) <= 2 {
		return nil
	}
	return dnsNames(payload[2:])
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func allowedPeer(allow []netip.AddrPort, p netip.AddrPort) bool {
	for _, a := range allow {
		if a.Addr().Unmap() == p.Addr() && (a.Port() == 0 || a.Port() == p.Port()) {
			return true
		}
	}
	return false
}

func sortedPeers(m map[netip.AddrPort]bool) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
