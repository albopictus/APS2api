package transport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bsfdsagfadg/vertex/internal/netx"
	"github.com/metacubex/mihomo/component/resolver"
	"github.com/miekg/dns"
)

type dnsTestRoute struct {
	Name, Proxy, Entry string
}

func TestMihomoDNSUnchangedWithoutTermuxNameservers(t *testing.T) {
	original := resolver.SystemResolver
	configureTermuxMihomoDNS(nil)
	if resolver.SystemResolver != original {
		t.Fatal("Mihomo DNS changed without Termux nameservers")
	}
}

// Run in a fresh process so the test exercises Mihomo's production package
// initialization and Termux discovery, with no global resolver test hooks.
func TestTermuxDNSRoutes(t *testing.T) {
	if os.Getenv("APS_DNS_TEST_CHILD") == "1" {
		runTermuxDNSRoutes(t)
		return
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var pc net.PacketConn
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsLoopback() {
			pc, err = net.ListenPacket("udp4", net.JoinHostPort(ip.String(), "0"))
			if err == nil {
				break
			}
		}
	}
	if pc == nil {
		t.Skip("Termux discovery integration requires a bindable non-loopback IPv4 interface")
	}
	var queriesMu sync.Mutex
	queries := map[string]int{}
	dnsServer := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg).SetReply(req)
		for _, q := range req.Question {
			queriesMu.Lock()
			queries[q.Name]++
			queriesMu.Unlock()
			if !strings.HasSuffix(q.Name, ".termux.invalid.") {
				resp.Rcode = dns.RcodeNameError
			} else if q.Qtype == dns.TypeA {
				resp.Answer = append(resp.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET}, A: net.ParseIP("127.0.0.1")})
			}
		}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = dnsServer.ActivateAndServe() }()
	t.Cleanup(func() { _ = dnsServer.Shutdown() })

	prefix := t.TempDir()
	if err := os.MkdirAll(filepath.Join(prefix, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefix, "etc", "resolv.conf"), []byte("nameserver "+pc.LocalAddr().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "dns-route-ok")
	}))
	t.Cleanup(origin.Close)
	_, httpPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	type hello struct {
		serverName string
		protocols  []string
		grease     bool
	}
	hellos := make(chan hello, 32)
	tlsOrigin := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tlsOrigin.Config.ErrorLog = log.New(io.Discard, "", 0)
	tlsOrigin.TLS = &tls.Config{GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		grease := false
		for _, suite := range info.CipherSuites {
			if suite&0x0f0f == 0x0a0a {
				grease = true
			}
		}
		hellos <- hello{info.ServerName, append([]string(nil), info.SupportedProtos...), grease}
		return nil, nil
	}}
	tlsOrigin.StartTLS()
	t.Cleanup(tlsOrigin.Close)
	_, tlsPort, _ := net.SplitHostPort(strings.TrimPrefix(tlsOrigin.URL, "https://"))

	targets := make(chan string, 64)
	httpProxy := startDNSRouteProxy(t, "http", targets)
	socksProxy := startDNSRouteProxy(t, "socks5", targets)
	routes := []dnsTestRoute{
		{Name: "direct"},
		{Name: "http", Proxy: "http://proxy.termux.invalid:" + httpProxy},
		{Name: "socks5", Proxy: "socks5://proxy.termux.invalid:" + socksProxy},
		{Name: "mihomo-http", Proxy: testClashProxyURI(t, map[string]any{"name": "dns-http", "type": "http", "server": "mihomo.termux.invalid", "port": httpProxy})},
		{Name: "mihomo-socks5", Proxy: testClashProxyURI(t, map[string]any{"name": "dns-socks", "type": "socks5", "server": "mihomo.termux.invalid", "port": socksProxy})},
		{Name: "chain-socks-http", Entry: "socks5://entry.termux.invalid:" + socksProxy, Proxy: "http://candidate.remote.invalid:" + httpProxy},
		{Name: "chain-http-socks", Entry: "http://entry.termux.invalid:" + httpProxy, Proxy: "socks5://candidate.remote.invalid:" + socksProxy},
	}
	routeJSON, err := json.Marshal(routes)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTermuxDNSRoutes$", "-test.v")
	// Setenv replaces inherited values instead of appending duplicate keys.
	t.Setenv("TERMUX_VERSION", "dns-regression")
	t.Setenv("PREFIX", prefix)
	t.Setenv("APS_DNS_TEST_CHILD", "1")
	t.Setenv("APS_DNS_TEST_ROUTES", string(routeJSON))
	t.Setenv("APS_DNS_TEST_HTTP_PORT", httpPort)
	t.Setenv("APS_DNS_TEST_TLS_PORT", tlsPort)
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Termux routing subprocess failed: %v\n%s", err, output)
	}
	t.Logf("%s", output)
	for range routes {
		select {
		case got := <-hellos:
			if got.serverName != "origin.remote.invalid" && got.serverName != "direct.termux.invalid" {
				t.Errorf("DNS changed TLS SNI: %q", got.serverName)
			}
			if !got.grease || !slices.Contains(got.protocols, "h2") || !slices.Contains(got.protocols, "http/1.1") {
				t.Errorf("Chrome ClientHello fingerprint lost: %+v", got)
			}
		default:
			t.Fatal("missing TLS ClientHello")
		}
	}
	queriesMu.Lock()
	defer queriesMu.Unlock()
	for _, host := range []string{"direct.termux.invalid.", "proxy.termux.invalid.", "mihomo.termux.invalid.", "entry.termux.invalid."} {
		if queries[host] == 0 {
			t.Errorf("route did not use Termux DNS for %s", host)
		}
	}
	for _, host := range []string{"origin.remote.invalid.", "candidate.remote.invalid."} {
		if queries[host] != 0 {
			t.Errorf("proxy destination leaked into local DNS: %s", host)
		}
	}
	seenRemote, seenCandidate := false, false
	for len(targets) > 0 {
		target := <-targets
		seenRemote = seenRemote || strings.HasPrefix(target, "origin.remote.invalid:")
		seenCandidate = seenCandidate || strings.HasPrefix(target, "candidate.remote.invalid:")
	}
	if !seenRemote || !seenCandidate {
		t.Fatal("proxy handshakes did not preserve remote hostnames")
	}
}

func runTermuxDNSRoutes(t *testing.T) {
	// Any accidental use of Go's default DNS fails immediately.
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("system DNS must not be used")
	}}
	var routes []dnsTestRoute
	if err := json.Unmarshal([]byte(os.Getenv("APS_DNS_TEST_ROUTES")), &routes); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(StopAllProxies)
	t.Run("standard-http-client", func(t *testing.T) {
		client := netx.NewHTTPClient(3 * time.Second)
		client.Transport.(*http.Transport).Proxy = nil
		defer client.CloseIdleConnections()
		resp, err := client.Get("http://direct.termux.invalid:" + os.Getenv("APS_DNS_TEST_HTTP_PORT"))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil || resp.StatusCode != 200 || string(body) != "dns-route-ok" {
			t.Fatalf("standard HTTP DNS fallback: status=%d body=%q err=%v", resp.StatusCode, body, err)
		}
	})
	for _, route := range routes {
		t.Run(route.Name, func(t *testing.T) {
			client := NewNetworkClient(false)
			sess, err := client.CreateSessionContext(WithEntryProxy(context.Background(), route.Entry), 3, route.Proxy, "dns-test")
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			host := "origin.remote.invalid"
			if route.Proxy == "" {
				host = "direct.termux.invalid"
			}
			status, body, err := sess.DoAndRead(context.Background(), "GET", "http://"+net.JoinHostPort(host, os.Getenv("APS_DNS_TEST_HTTP_PORT")), nil, nil)
			if err != nil || status != 200 || string(body) != "dns-route-ok" {
				t.Fatalf("HTTP route: status=%d body=%q err=%v", status, body, err)
			}
			_, _, err = sess.DoAndRead(context.Background(), "GET", "https://"+net.JoinHostPort(host, os.Getenv("APS_DNS_TEST_TLS_PORT")), nil, nil)
			// The fixture certificate is intentionally untrusted. Verify that
			// certificate validation stays enabled while capturing ClientHello.
			if err == nil || !strings.Contains(err.Error(), "certificate") {
				t.Fatalf("TLS certificate verification was not preserved: %v", err)
			}
		})
	}
	t.Run("proxy-failure-does-not-fall-back-to-direct", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := listener.Addr().String()
		_ = listener.Close()
		sess, err := NewNetworkClient(false).CreateSessionWithoutEntryProxy(1, "http://"+addr, "failed-proxy")
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()
		_, _, err = sess.DoAndRead(context.Background(), "GET", "http://direct.termux.invalid:"+os.Getenv("APS_DNS_TEST_HTTP_PORT"), nil, nil)
		if err == nil {
			t.Fatal("failed proxy silently fell back to direct")
		}
	})
}

func startDNSRouteProxy(t *testing.T, scheme string, targets chan<- string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				reader := bufio.NewReader(conn)
				target, err := readDNSProxyTarget(conn, reader, scheme)
				if err != nil {
					return
				}
				targets <- target
				_, port, err := net.SplitHostPort(target)
				if err != nil {
					return
				}
				upstream, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), time.Second)
				if err != nil {
					return
				}
				defer upstream.Close()
				if scheme == "http" {
					_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				} else {
					_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				}
				done := make(chan struct{})
				go func() {
					_, _ = io.Copy(upstream, reader)
					_ = upstream.Close()
					close(done)
				}()
				_, _ = io.Copy(conn, upstream)
				_ = conn.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-acceptDone; wg.Wait() })
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	return port
}

func readDNSProxyTarget(conn net.Conn, reader *bufio.Reader, scheme string) (string, error) {
	if scheme == "http" {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return "", err
		}
		_ = req.Body.Close()
		if req.Method != "CONNECT" {
			return "", fmt.Errorf("expected CONNECT, got %s", req.Method)
		}
		return req.Host, nil
	}
	var greeting [2]byte
	if _, err := io.ReadFull(reader, greeting[:]); err != nil {
		return "", err
	}
	if _, err := io.CopyN(io.Discard, reader, int64(greeting[1])); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return "", err
	}
	var host string
	switch header[3] {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(reader, ip[:]); err != nil {
			return "", err
		}
		host = net.IP(ip[:]).String()
	case 3:
		size, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		name := make([]byte, size)
		if _, err := io.ReadFull(reader, name); err != nil {
			return "", err
		}
		host = string(name)
	default:
		return "", fmt.Errorf("unexpected SOCKS address type %d", header[3])
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}
