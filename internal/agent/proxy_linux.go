//go:build linux

package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netns"
)

// A linked network's proxy: an HTTP proxy on a loopback address of the device's own namespace that
// opens connections into the linked network from inside its namespace. For programs that need the
// linked network and the rest of the world at the same time and cannot run inside the namespace
// (e.g. a metrics collector scraping several networks). It only reaches addresses of the linked
// network (by address, or by a name of the namespace's hosts file), supports CONNECT and plain
// HTTP requests, and listens only on loopback: anything that can reach it runs on this device. With
// a list of ports it opens connections to those ports only (refusals are logged): every program on
// the device can use the proxy, so it should reach no more than what it is for.
//
// Asked for with `ento agent link --proxy ADDRESS:PORT [--proxy-ports P,P] NAME`, kept in
// links/<name>/proxy ("ADDRESS:PORT[ P,P]").

const proxyFile = "proxy"

// SetLinkProxy asks the running agent to serve (addr) or stop (empty addr) a linked network's proxy;
// ports, when not empty ("443,9199"), are the only ports it opens connections to.
func SetLinkProxy(stateDir, name, addr, ports string) error {
	path := filepath.Join(LinksDir(stateDir), name, proxyFile)
	if addr == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if _, err := parseProxyAddr(addr); err != nil {
		return err
	}
	setting := addr
	if ports != "" {
		if _, err := parsePorts(ports); err != nil {
			return err
		}
		setting += " " + ports
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(setting), 0o600)
}

// parsePorts reads "443,9199": the ports a proxy may open connections to.
func parsePorts(s string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("proxy ports %q: a comma-separated list of ports, e.g. 443,9199", s)
		}
		out[strconv.Itoa(n)] = true
	}
	return out, nil
}

// splitProxySetting reads a proxy file: its address and, if any, its allowed ports (nil: all).
func splitProxySetting(setting string) (string, map[string]bool, error) {
	f := strings.Fields(setting)
	switch len(f) {
	case 1:
		return f[0], nil, nil
	case 2:
		ports, err := parsePorts(f[1])
		return f[0], ports, err
	}
	return "", nil, fmt.Errorf("proxy setting %q: address[ ports]", setting)
}

// LinkProxy returns the proxy address asked for a linked network, if any.
func LinkProxy(stateDir, name string) string {
	b, _ := os.ReadFile(filepath.Join(LinksDir(stateDir), name, proxyFile))
	return strings.TrimSpace(string(b))
}

func parseProxyAddr(addr string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("proxy address %q: must be a loopback address and a port, e.g. 127.0.0.1:9180", addr)
	}
	return ap, nil
}

type linkProxy struct {
	setting string // as in the proxy file: address and allowed ports
	srv     *http.Server
}

// startLinkProxy serves a linked network's proxy as setting says (address[ ports]) until stopped.
func startLinkProxy(link string, ns netns.NsHandle, network netip.Prefix, setting string, logf func(string, ...any)) (*linkProxy, error) {
	addr, ports, err := splitProxySetting(setting)
	if err != nil {
		return nil, err
	}
	if _, err := parseProxyAddr(addr); err != nil {
		return nil, err
	}
	var refusedMu sync.Mutex
	refused := map[string]time.Time{} // when a refusal for a port was last logged (once a minute each)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	dial := dialIn(ns)
	// dialLinked resolves host inside the linked network only and refuses anything outside it.
	dialLinked := func(ctx context.Context, hostport string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(hostport)
		if err != nil {
			return nil, err
		}
		if ports != nil && !ports[port] {
			refusedMu.Lock()
			if time.Since(refused[port]) > time.Minute {
				refused[port] = time.Now()
				logf("link %s: proxy: refused a connection to %q (port %s is not allowed)", link, hostport, port)
			}
			refusedMu.Unlock()
			return nil, fmt.Errorf("port %s is not allowed through this proxy", port)
		}
		ip, err := resolveLinked(link, host)
		if err != nil {
			return nil, err
		}
		if !network.Contains(ip) {
			return nil, fmt.Errorf("%s is not in linked network %s", host, network)
		}
		return dial(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
	}
	transport := &http.Transport{
		DialContext:         func(ctx context.Context, _, addr string) (net.Conn, error) { return dialLinked(ctx, addr) },
		MaxIdleConnsPerHost: 4, IdleConnTimeout: time.Minute, ResponseHeaderTimeout: time.Minute,
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			up, err := dialLinked(r.Context(), r.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				up.Close()
				http.Error(w, "hijacking not supported", http.StatusInternalServerError)
				return
			}
			c, buf, err := hj.Hijack()
			if err != nil {
				up.Close()
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			go splice(c, buf, up)
			return
		}
		if r.URL.Host == "" || r.URL.Scheme != "http" {
			http.Error(w, "only CONNECT and http:// requests are proxied", http.StatusBadRequest)
			return
		}
		out := r.Clone(r.Context())
		out.RequestURI = ""
		for _, hh := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"} {
			out.Header.Del(hh)
		}
		resp, err := transport.RoundTrip(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
	p := &linkProxy{setting: setting, srv: &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}}
	go func() {
		if err := p.srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("proxy %s: %v", addr, err)
		}
	}()
	return p, nil
}

func (p *linkProxy) stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = p.srv.Shutdown(ctx)
}

// splice copies between a hijacked client connection (and what it already buffered) and up.
func splice(c net.Conn, buf *bufio.ReadWriter, up net.Conn) {
	defer c.Close()
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() {
		if n := buf.Reader.Buffered(); n > 0 {
			b, _ := buf.Reader.Peek(n)
			_, _ = up.Write(b)
		}
		_, _ = io.Copy(up, c)
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, up)
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// resolveLinked turns host into an address using only the linked network: an IPv4 literal, or a
// name from the namespace's hosts file (never the host's DNS).
func resolveLinked(link, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap(), nil
	}
	f, err := os.Open(filepath.Join(netnsEtcDir, NamespaceName(link), "hosts"))
	if err != nil {
		return netip.Addr{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		for _, n := range fields[1:] {
			if n == host {
				if ip, err := netip.ParseAddr(fields[0]); err == nil {
					return ip, nil
				}
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("%s: no such name in linked network %s", host, link)
}
