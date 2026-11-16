package capture

import (
	"bytes"
	"encoding/binary"
	"flag"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Run "go test ./resources/test/capture -update" to write the fixtures again.
var update = flag.Bool("update", false, "write the pcap fixtures in testdata/")

var (
	localV4   = netip.MustParseAddr("172.30.0.3")
	localV6   = netip.MustParseAddr("fd00:30::3")
	pgV4      = netip.MustParseAddr("172.30.0.2")
	hostV4    = netip.MustParseAddr("172.30.0.4")
	gatewayV4 = netip.MustParseAddr("172.30.0.1")
	otherV4   = netip.MustParseAddr("203.0.113.9")
	otherV6   = netip.MustParseAddr("2001:db8::9")
)

func testAllow() Allow {
	return Allow{
		Peers: []netip.AddrPort{
			netip.AddrPortFrom(pgV4, 5432),
			netip.AddrPortFrom(hostV4, 40001),
			netip.AddrPortFrom(hostV4, 40002),
		},
		DNSNames: []string{"postgres", "host.testcontainers.internal"},
	}
}

func testLocal() []netip.Addr {
	return []netip.Addr{localV4, localV6, netip.MustParseAddr("127.0.0.1")}
}

type pkt struct {
	linkType layers.LinkType
	data     []byte
}

// sllHeader returns the 16-byte header of a Linux cooked capture.
func sllHeader(proto layers.EthernetType, outgoing bool) []byte {
	h := make([]byte, 16)
	if outgoing {
		binary.BigEndian.PutUint16(h[0:], 4)
	}
	binary.BigEndian.PutUint16(h[2:], 1)
	binary.BigEndian.PutUint16(h[4:], 6)
	binary.BigEndian.PutUint16(h[14:], uint16(proto))
	return h
}

// sll2Header returns the 20-byte header of a Linux cooked capture, version 2.
func sll2Header(proto layers.EthernetType) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], uint16(proto))
	binary.BigEndian.PutUint32(h[4:], 2)
	binary.BigEndian.PutUint16(h[8:], 1)
	h[11] = 6
	return h
}

func ipLayer(src, dst netip.Addr, proto layers.IPProtocol) (gopacket.SerializableLayer, layers.EthernetType, gopacket.NetworkLayer) {
	if src.Is4() {
		ip := &layers.IPv4{
			Version: 4, IHL: 5, TTL: 64, Protocol: proto,
			SrcIP: net.IP(src.AsSlice()), DstIP: net.IP(dst.AsSlice()),
		}
		return ip, layers.EthernetTypeIPv4, ip
	}
	ip := &layers.IPv6{
		Version: 6, HopLimit: 64, NextHeader: proto,
		SrcIP: net.IP(src.AsSlice()), DstIP: net.IP(dst.AsSlice()),
	}
	return ip, layers.EthernetTypeIPv6, ip
}

func serialize(t *testing.T, linkType layers.LinkType, src, dst netip.Addr, tr gopacket.SerializableLayer, payload []byte) pkt {
	t.Helper()
	var proto layers.IPProtocol
	switch tr.(type) {
	case *layers.TCP:
		proto = layers.IPProtocolTCP
	case *layers.UDP:
		proto = layers.IPProtocolUDP
	}
	ipl, et, nl := ipLayer(src, dst, proto)
	switch l := tr.(type) {
	case *layers.TCP:
		_ = l.SetNetworkLayerForChecksum(nl)
	case *layers.UDP:
		_ = l.SetNetworkLayerForChecksum(nl)
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ls := []gopacket.SerializableLayer{ipl, tr}
	if payload != nil {
		ls = append(ls, gopacket.Payload(payload))
	}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatal(err)
	}
	var hdr []byte
	switch linkType {
	case layers.LinkTypeLinuxSLL2:
		hdr = sll2Header(et)
	default:
		hdr = sllHeader(et, true)
	}
	return pkt{linkType: linkType, data: append(hdr, buf.Bytes()...)}
}

func tcpSYN(t *testing.T, src, dst netip.Addr, dport uint16, ack bool) pkt {
	t.Helper()
	tcp := &layers.TCP{SrcPort: 50000, DstPort: layers.TCPPort(dport), SYN: true, ACK: ack, Window: 1000}
	return serialize(t, layers.LinkTypeLinuxSLL, src, dst, tcp, nil)
}

func dnsQuery(t *testing.T, linkType layers.LinkType, src netip.Addr, name string) pkt {
	t.Helper()
	d := &layers.DNS{
		ID: 7, RD: true, QDCount: 1,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
	}
	buf := gopacket.NewSerializeBuffer()
	if err := d.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatal(err)
	}
	udp := &layers.UDP{SrcPort: 51000, DstPort: 43211}
	return serialize(t, linkType, src, DockerDNS, udp, buf.Bytes())
}

func pcapBytes(t *testing.T, linkType layers.LinkType, pkts ...pkt) []byte {
	t.Helper()
	var b bytes.Buffer
	w := pcapgo.NewWriter(&b)
	if err := w.WriteFileHeader(512, linkType); err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(1_700_000_000, 0)
	for _, p := range pkts {
		ci := gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(p.data), Length: len(p.data)}
		if err := w.WritePacket(ci, p.data); err != nil {
			t.Fatal(err)
		}
		ts = ts.Add(time.Millisecond)
	}
	return b.Bytes()
}

func fixtures(t *testing.T) map[string][]byte {
	t.Helper()
	sll := layers.LinkTypeLinuxSLL
	loop := tcpSYN(t, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1"), 8080, false)
	return map[string][]byte{
		"allowed.pcap": pcapBytes(t, sll,
			tcpSYN(t, localV4, pgV4, 5432, false),
			tcpSYN(t, localV4, hostV4, 40001, false),
			tcpSYN(t, localV4, hostV4, 40002, false),
			dnsQuery(t, sll, localV4, "postgres."),
			dnsQuery(t, sll, localV4, "host.testcontainers.internal"),
			loop,
		),
		"dns_unexpected.pcap": pcapBytes(t, sll,
			dnsQuery(t, sll, localV4, "postgres"),
			dnsQuery(t, sll, localV4, "getbifrost.ai"),
		),
		"dns_unexpected_sll2.pcap": pcapBytes(t, layers.LinkTypeLinuxSLL2,
			dnsQuery(t, layers.LinkTypeLinuxSLL2, localV4, "getbifrost.ai"),
		),
		"syn_unexpected.pcap": pcapBytes(t, sll,
			tcpSYN(t, localV4, pgV4, 5432, false),
			tcpSYN(t, localV4, otherV4, 443, false),
		),
		"inbound_syn.pcap": pcapBytes(t, sll,
			tcpSYN(t, gatewayV4, localV4, 8080, false),
		),
		"synack.pcap": pcapBytes(t, sll,
			tcpSYN(t, localV4, gatewayV4, 50000, true),
		),
		"ipv6_syn.pcap": pcapBytes(t, sll,
			tcpSYN(t, localV6, otherV6, 443, false),
		),
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func TestWriteFixtures(t *testing.T) {
	if !*update {
		t.Skip("run with -update to write the fixtures")
	}
	for name, data := range fixtures(t) {
		if err := os.WriteFile(filepath.Join("testdata", name), data, 0o644); err != nil { //nolint:gosec
			t.Fatal(err)
		}
	}
}

func analyzeFile(t *testing.T, name string) (Result, error) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // fixed fixture names
	if err != nil {
		t.Fatal(err)
	}
	return Analyze(bytes.NewReader(data), testLocal(), testAllow())
}

// U6: only allowed peers and allowed DNS names.
func TestU6AllowedOnly(t *testing.T) {
	res, err := analyzeFile(t, "allowed.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		t.Fatalf("unexpected peers %v, unexpected names %v", res.UnexpectedPeers, res.UnexpectedDNSNames)
	}
	if len(res.Peers) != 3 || len(res.DNSNames) != 2 {
		t.Fatalf("peers %v, names %v: the analyzer did not read the fixture", res.Peers, res.DNSNames)
	}
}

// U7: a DNS query for getbifrost.ai to the Docker DNS on a random port.
func TestU7UnexpectedDNSName(t *testing.T) {
	for _, name := range []string{"dns_unexpected.pcap", "dns_unexpected_sll2.pcap"} {
		res, err := analyzeFile(t, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(res.UnexpectedDNSNames) != 1 || res.UnexpectedDNSNames[0] != "getbifrost.ai" {
			t.Fatalf("%s: unexpected names %v, want [getbifrost.ai]", name, res.UnexpectedDNSNames)
		}
		if len(res.UnexpectedPeers) != 0 {
			t.Fatalf("%s: unexpected peers %v, want none", name, res.UnexpectedPeers)
		}
	}
}

// U8: a TCP SYN to an IPv4 address that is not in the allow list.
func TestU8UnexpectedPeer(t *testing.T) {
	res, err := analyzeFile(t, "syn_unexpected.pcap")
	if err != nil {
		t.Fatal(err)
	}
	want := netip.AddrPortFrom(otherV4, 443)
	if len(res.UnexpectedPeers) != 1 || res.UnexpectedPeers[0] != want {
		t.Fatalf("unexpected peers %v, want [%v]", res.UnexpectedPeers, want)
	}
}

// U9: an empty file, a truncated file, and a file that is not pcap.
func TestU9BadFiles(t *testing.T) {
	good := fixtures(t)["allowed.pcap"]
	cases := map[string][]byte{
		"empty":         {},
		"truncated":     good[:len(good)-10],
		"header only":   good[:24],
		"not pcap":      []byte("this is not a pcap file, it is text of enough length"),
		"short header":  good[:10],
		"zero packets":  pcapBytes(t, layers.LinkTypeLinuxSLL),
		"garbage bytes": bytes.Repeat([]byte{0xde, 0xad}, 64),
	}
	for name, data := range cases {
		res, err := Analyze(bytes.NewReader(data), testLocal(), testAllow())
		if err == nil {
			t.Errorf("%s: no error, result %+v", name, res)
		}
	}
}

// U10: an inbound SYN from the Docker gateway to local port 8080.
func TestU10InboundSYN(t *testing.T) {
	res, err := analyzeFile(t, "inbound_syn.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || len(res.Peers) != 0 {
		t.Fatalf("result %+v, want no peer", res)
	}
}

// U11: a SYN-ACK from the local address to the Docker gateway.
func TestU11SYNACK(t *testing.T) {
	res, err := analyzeFile(t, "synack.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() || len(res.Peers) != 0 {
		t.Fatalf("result %+v, want no peer", res)
	}
}

// U12: a TCP SYN from a local IPv6 address to an IPv6 address that is not in
// the allow list.
func TestU12IPv6(t *testing.T) {
	res, err := analyzeFile(t, "ipv6_syn.pcap")
	if err != nil {
		t.Fatal(err)
	}
	want := netip.AddrPortFrom(otherV6, 443)
	if len(res.UnexpectedPeers) != 1 || res.UnexpectedPeers[0] != want {
		t.Fatalf("unexpected peers %v, want [%v]", res.UnexpectedPeers, want)
	}
}
