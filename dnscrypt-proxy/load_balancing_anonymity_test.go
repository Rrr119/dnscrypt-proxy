package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"github.com/BurntSushi/toml"
	"github.com/VividCortex/ewma"
	stamps "github.com/jedisct1/go-dnsstamps"
)

type anonLBUDPObservation struct {
	from *net.UDPAddr
	data []byte
	name string
}

func newAnonLBUDPSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	return conn
}

func anonLBReceiveUDPObservations(conn *net.UDPConn, observations chan<- anonLBUDPObservation) {
	buffer := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		observations <- anonLBUDPObservation{from: from, data: bytes.Clone(buffer[:n])}
	}
}

func anonLBForwardRelay(
	conn *net.UDPConn,
	name string,
	observations chan<- anonLBUDPObservation,
	forwardErrors chan<- error,
) {
	buffer := make([]byte, 65535)
	for {
		n, from, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		packet := bytes.Clone(buffer[:n])
		observations <- anonLBUDPObservation{from: from, data: packet, name: name}
		if n < anonymizedDNSHeaderSize {
			forwardErrors <- fmt.Errorf("relay received %d bytes, shorter than Anonymized DNS header", n)
			continue
		}
		target := &net.UDPAddr{
			IP:   net.IP(bytes.Clone(packet[10:26])),
			Port: int(binary.BigEndian.Uint16(packet[26:28])),
		}
		if _, err := conn.WriteToUDP(packet[anonymizedDNSHeaderSize:], target); err != nil {
			forwardErrors <- fmt.Errorf("forward relayed query: %w", err)
			return
		}
	}
}

func newAnonLBServersInfo(t *testing.T, count int) *ServersInfo {
	t.Helper()
	serversInfo := NewServersInfo()
	for i := range count {
		serversInfo.inner = append(serversInfo.inner, &ServerInfo{
			Name: fmt.Sprintf("upstream-%d", i),
		})
	}
	return &serversInfo
}

func TestThreeUpstreamRoundRobinDistribution(t *testing.T) {
	serversInfo := newAnonLBServersInfo(t, 3)
	serversInfo.lbStrategy = LBStrategyRoundRobin{}

	counts := make(map[string]int, 3)
	const queries = 30
	for range queries {
		serverInfo := serversInfo.getOne()
		if serverInfo == nil {
			t.Fatal("load balancer returned no upstream")
		}
		counts[serverInfo.Name]++
	}

	want := map[string]int{"upstream-0": 10, "upstream-1": 10, "upstream-2": 10}
	if !reflect.DeepEqual(counts, want) {
		t.Fatalf("distribution = %v, want %v", counts, want)
	}
}

func TestDefaultLoadBalancerSpreadsAcrossThreeUpstreams(t *testing.T) {
	serversInfo := newAnonLBServersInfo(t, 3)

	counts := make(map[string]int, 3)
	const queries = 6000
	for range queries {
		serverInfo := serversInfo.getOne()
		if serverInfo == nil {
			t.Fatal("load balancer returned no upstream")
		}
		counts[serverInfo.Name]++
	}

	for name, count := range counts {
		if count < queries/5 || count > queries*2/5 {
			t.Fatalf("upstream %s received %d queries; expected an approximately equal share", name, count)
		}
	}
}

func TestLoadBalancingAndAnonymizedRoutesConfigCompatibility(t *testing.T) {
	config := newConfig()
	metadata, err := toml.Decode(`
server_names = ["upstream-0", "upstream-1", "upstream-2"]
lb_strategy = "round_robin"

[anonymized_dns]
skip_incompatible = true

[[anonymized_dns.routes]]
server_name = "*"
via = ["relay-0"]
`, &config)
	if err != nil {
		t.Fatal(err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) != 0 {
		t.Fatalf("unsupported configuration keys: %v", undecoded)
	}
	if got, want := config.ServerNames, []string{"upstream-0", "upstream-1", "upstream-2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("server_names = %v, want %v", got, want)
	}
	if len(config.AnonymizedDNS.Routes) != 1 {
		t.Fatalf("routes count = %d, want 1", len(config.AnonymizedDNS.Routes))
	}

	proxy := &Proxy{serversInfo: NewServersInfo()}
	configureLoadBalancing(proxy, &config)
	if _, ok := proxy.serversInfo.lbStrategy.(LBStrategyRoundRobin); !ok {
		t.Fatalf("lb strategy = %T, want LBStrategyRoundRobin", proxy.serversInfo.lbStrategy)
	}
	configureAnonymizedDNS(proxy, &config)
	if got := (*proxy.routes)["*"]; !reflect.DeepEqual(got, []string{"relay-0"}) {
		t.Fatalf("wildcard route = %v, want [relay-0]", got)
	}

	defaultConfig := newConfig()
	configureLoadBalancing(proxy, &defaultConfig)
	if _, ok := proxy.serversInfo.lbStrategy.(LBStrategyWP2); !ok {
		t.Fatalf("default lb strategy = %T, want LBStrategyWP2", proxy.serversInfo.lbStrategy)
	}

	for _, strategyName := range []string{"round_robin", "round-robin", "roundrobin", "rr"} {
		strategyConfig := newConfig()
		strategyConfig.LBStrategy = strategyName
		configureLoadBalancing(proxy, &strategyConfig)
		if _, ok := proxy.serversInfo.lbStrategy.(LBStrategyRoundRobin); !ok {
			t.Fatalf("%s mapped to %T, want LBStrategyRoundRobin", strategyName, proxy.serversInfo.lbStrategy)
		}
	}
}

func TestThreeUpstreamsAreDistributedThroughAnonymousRelays(t *testing.T) {
	const upstreamCount = 3
	const queries = 12

	upstreamConns := make([]*net.UDPConn, upstreamCount)
	relayConns := make([]*net.UDPConn, upstreamCount)
	upstreamObservations := make(chan anonLBUDPObservation, queries)
	relayObservations := make(chan anonLBUDPObservation, queries)
	relayErrors := make(chan error, queries)

	for i := range upstreamCount {
		upstreamConns[i] = newAnonLBUDPSocket(t)
		relayConns[i] = newAnonLBUDPSocket(t)
		go anonLBReceiveUDPObservations(upstreamConns[i], upstreamObservations)
		go anonLBForwardRelay(relayConns[i], fmt.Sprintf("relay-%d", i), relayObservations, relayErrors)
	}

	routes := make(map[string][]string, upstreamCount)
	proxy := &Proxy{serversInfo: NewServersInfo(), routes: &routes}
	serversInfo := &proxy.serversInfo

	relayAddrToUpstream := make(map[string]string, upstreamCount)
	for i := range upstreamCount {
		serverName := fmt.Sprintf("upstream-%d", i)
		relayName := fmt.Sprintf("relay-%d", i)
		upstreamAddr := upstreamConns[i].LocalAddr().(*net.UDPAddr)
		relayAddr := relayConns[i].LocalAddr().(*net.UDPAddr)

		serversInfo.registerRelay(relayName, stamps.ServerStamp{
			Proto:         stamps.StampProtoTypeDNSCryptRelay,
			ServerAddrStr: relayAddr.String(),
		})
		routes[serverName] = []string{relayName}
		relayAddrToUpstream[relayAddr.String()] = upstreamAddr.String()
	}

	for i := range upstreamCount {
		serverName := fmt.Sprintf("upstream-%d", i)
		relayName := fmt.Sprintf("relay-%d", i)
		upstreamAddr := upstreamConns[i].LocalAddr().(*net.UDPAddr)
		relay, err := route(proxy, serverName, stamps.StampProtoTypeDNSCrypt)
		if err != nil {
			t.Fatalf("route for %s: %v", serverName, err)
		}
		if relay == nil || relay.Dnscrypt == nil {
			t.Fatalf("route for %s did not select a DNSCrypt relay", serverName)
		}
		if relay.Name != relayName {
			t.Fatalf("route for %s selected relay name %q, want %q", serverName, relay.Name, relayName)
		}
		serversInfo.inner = append(serversInfo.inner, &ServerInfo{
			Name:               serverName,
			UDPAddr:            upstreamAddr,
			Relay:              relay,
			CryptoConstruction: XSalsa20Poly1305,
			SharedKey:          [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			rtt:                ewma.NewMovingAverage(RTTEwmaDecay),
		})
	}
	serversInfo.lbStrategy = LBStrategyRoundRobin{}

	clientConn := newAnonLBUDPSocket(t)
	dnsProxy := &Proxy{}
	if err := dnsProxy.initDNSCryptClientKey(); err != nil {
		t.Fatal(err)
	}
	query := dns.NewMsg("hidden-relay-test.example.", dns.TypeA)
	if err := query.Pack(); err != nil {
		t.Fatal(err)
	}
	plaintextMarker := []byte("hidden-relay-test")
	if !bytes.Contains(query.Data, plaintextMarker) {
		t.Fatal("packed test query does not contain the plaintext query marker")
	}
	_, encryptedQuery, _, _, err := dnsProxy.Encrypt(serversInfo.inner[0], query.Data, "udp")
	if err != nil {
		t.Fatalf("encrypt query: %v", err)
	}
	if len(encryptedQuery) <= len(query.Data) {
		t.Fatalf("encrypted query length %d is not larger than plaintext %d", len(encryptedQuery), len(query.Data))
	}
	if bytes.Contains(encryptedQuery, plaintextMarker) {
		t.Fatal("encrypted DNSCrypt query still contains the plaintext query name")
	}
	queryPayload := bytes.Clone(encryptedQuery)

	selectionCounts := make(map[string]int, upstreamCount)
	for range queries {
		serverInfo := serversInfo.getOne()
		if serverInfo == nil {
			t.Fatal("load balancer returned no upstream")
		}
		selectionCounts[serverInfo.Name]++

		packet := bytes.Clone(queryPayload)
		dnsProxy.prepareForRelay(serverInfo.UDPAddr.IP, serverInfo.UDPAddr.Port, &packet)
		if !bytes.HasPrefix(packet, bytes.Repeat([]byte{0xff}, 8)) {
			t.Fatal("relayed packet is missing the Anonymized DNS preamble")
		}
		if bytes.Contains(packet, plaintextMarker) {
			t.Fatal("relayed packet leaks the plaintext query name")
		}
		exchangeAddr := dnsCryptUDPExchangeAddr(serverInfo)
		if exchangeAddr.String() != serverInfo.Relay.Dnscrypt.RelayUDPAddr.String() {
			t.Fatalf("exchange address %v is not relay %v", exchangeAddr, serverInfo.Relay.Dnscrypt.RelayUDPAddr)
		}
		if _, err := clientConn.WriteToUDP(packet, exchangeAddr); err != nil {
			t.Fatalf("send relayed query: %v", err)
		}
	}

	wantSelections := map[string]int{"upstream-0": 4, "upstream-1": 4, "upstream-2": 4}
	if !reflect.DeepEqual(selectionCounts, wantSelections) {
		t.Fatalf("selection counts = %v, want %v", selectionCounts, wantSelections)
	}

	upstreamByRelay := make(map[string]int, upstreamCount)
	for range queries {
		select {
		case observation := <-upstreamObservations:
			upstreamByRelay[observation.from.String()]++
			if !bytes.Equal(observation.data, queryPayload) {
				t.Fatal("upstream received a payload different from the encrypted DNSCrypt query")
			}
		case err := <-relayErrors:
			t.Fatalf("test relay error: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for a relayed query at an upstream")
		}
	}

	wantUpstreamCounts := make(map[string]int, upstreamCount)
	for relayAddr := range relayAddrToUpstream {
		wantUpstreamCounts[relayAddr] = 4
	}
	if !reflect.DeepEqual(upstreamByRelay, wantUpstreamCounts) {
		t.Fatalf("upstream source addresses = %v, want each relay to source four queries", upstreamByRelay)
	}

	relayCounts := make(map[string]int, upstreamCount)
	for range queries {
		select {
		case observation := <-relayObservations:
			relayCounts[observation.name]++
			if observation.from.String() != clientConn.LocalAddr().String() {
				t.Fatalf("relay saw client %v, want %v", observation.from, clientConn.LocalAddr())
			}
			target := &net.UDPAddr{
				IP:   net.IP(bytes.Clone(observation.data[10:26])),
				Port: int(binary.BigEndian.Uint16(observation.data[26:28])),
			}
			targetString := target.String()
			foundTarget := false
			for _, upstreamAddr := range relayAddrToUpstream {
				if upstreamAddr == targetString {
					foundTarget = true
					break
				}
			}
			if !foundTarget {
				t.Fatalf("relay envelope targets unknown upstream %s", targetString)
			}
		case err := <-relayErrors:
			t.Fatalf("test relay error: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for relay observation")
		}
	}

	select {
	case err := <-relayErrors:
		t.Fatalf("unexpected relay error: %v", err)
	default:
	}

	wantRelayCounts := map[string]int{"relay-0": 4, "relay-1": 4, "relay-2": 4}
	if !reflect.DeepEqual(relayCounts, wantRelayCounts) {
		t.Fatalf("relay counts = %v, want %v", relayCounts, wantRelayCounts)
	}
}
