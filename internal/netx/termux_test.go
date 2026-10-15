package netx

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestTermuxDialerUsesDiscoveredDNS(t *testing.T) {
	// Seed discovery with a local DNS fixture; never contact public DNS.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg).SetReply(req)
		for _, q := range req.Question {
			if q.Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.42")})
			}
		}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	oldAddrs := termuxNameserverAddrs
	termuxNameserverOnce.Do(func() {})
	termuxNameserverAddrs = []string{pc.LocalAddr().String()}
	t.Cleanup(func() {
		termuxNameserverAddrs = oldAddrs
		termuxNameserverOnce = sync.Once{}
	})
	t.Setenv("TERMUX_VERSION", "test")
	dialer := NewDialer(time.Second)
	if dialer.Resolver == nil || !dialer.Resolver.PreferGo {
		t.Fatal("Termux dialer did not install the Go DNS fallback")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := dialer.Resolver.LookupHost(ctx, "fallback.termux.invalid")
	if err != nil || len(ips) != 1 || ips[0] != "192.0.2.42" {
		t.Fatalf("fallback lookup: ips=%v err=%v", ips, err)
	}
	addrs := TermuxNameserverAddrs()
	addrs[0] = "changed"
	if TermuxNameserverAddrs()[0] != pc.LocalAddr().String() {
		t.Fatal("nameserver discovery exposed its cached slice")
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	_, err = dialer.Resolver.LookupHost(canceled, "canceled.termux.invalid")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lookup did not preserve cancellation: %v", err)
	}
}

func TestNonTermuxDialerPreservesSystemDNS(t *testing.T) {
	t.Setenv("TERMUX_VERSION", "")
	if isTermux() {
		t.Skip("running inside Termux")
	}
	if NewDialer(time.Second).Resolver != nil || TermuxNameserverAddrs() != nil {
		t.Fatal("non-Termux DNS was overridden")
	}
}

func TestNameserverResolverRetriesTCPWhenUDPTruncated(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg).SetReply(req)
		if w.LocalAddr().Network() == "udp" {
			resp.Truncated = true
		} else if req.Question[0].Qtype == dns.TypeA {
			resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("192.0.2.43")}}
		}
		_ = w.WriteMsg(resp)
	})
	udp := &dns.Server{PacketConn: pc, Handler: handler}
	tcp := &dns.Server{Listener: listener, Handler: handler}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() { _ = udp.Shutdown(); _ = tcp.Shutdown() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ips, err := newNameserverResolver([]string{listener.Addr().String()}).LookupHost(ctx, "tcp.termux.invalid")
	if err != nil || len(ips) != 1 || ips[0] != "192.0.2.43" {
		t.Fatalf("TCP fallback: ips=%v err=%v", ips, err)
	}
}

func TestParseResolvConfNameserversPrefersUsableServers(t *testing.T) {
	content := `
# comment
nameserver 127.0.0.1
nameserver ::1
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 8.8.8.8
`

	got := parseResolvConfNameservers(content)
	if len(got) != 2 {
		t.Fatalf("expected 2 usable nameservers, got %d: %#v", len(got), got)
	}
	if got[0] != "8.8.8.8:53" {
		t.Fatalf("unexpected first nameserver: %q", got[0])
	}
	if got[1] != "1.1.1.1:53" {
		t.Fatalf("unexpected second nameserver: %q", got[1])
	}
}

func TestNormalizeNameserverAddrSupportsIPv6AndRejectsLoopback(t *testing.T) {
	if got := normalizeNameserverAddr("2001:4860:4860::8888"); got != "[2001:4860:4860::8888]:53" {
		t.Fatalf("unexpected IPv6 address: %q", got)
	}
	if got := normalizeNameserverAddr("[2606:4700:4700::1111]:5353"); got != "[2606:4700:4700::1111]:5353" {
		t.Fatalf("unexpected IPv6 host:port: %q", got)
	}
	if got := normalizeNameserverAddr("127.0.0.1:53"); got != "" {
		t.Fatalf("loopback should be rejected, got %q", got)
	}
}
