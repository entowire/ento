package control

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/store"
)

// The admin interface at scale (docs/plan.md, "the dashboard at scale"): a control node with 100+
// of everything (people, devices, people and device groups, invitations, rules, device checks,
// routes, names, links, activity), the real page in headless Chromium through the admin device's
// tunnel, every page at a desktop and a phone width, light and dark. Each page must load within
// its budget and nothing may stick out sideways; screenshots and a report go to ENTO_TEST_SHOTS
// (default: the test's temporary directory). It runs only where ENTO_TEST_BROWSER names a
// Chromium (or chrome-headless-shell) binary.
func TestUIAtScale(t *testing.T) {
	bin := os.Getenv("ENTO_TEST_BROWSER")
	if bin == "" {
		t.Skip("ENTO_TEST_BROWSER not set")
	}
	shots := os.Getenv("ENTO_TEST_SHOTS")
	if shots == "" {
		shots = t.TempDir()
	}
	if err := os.MkdirAll(shots, 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv, st, admin := startScaleUI(t, ctx)
	counts := fillAtScale(t, ctx, srv, st)
	t.Logf("data: %v", counts)

	proxy := tunnelProxy(t, admin, srv.Address())
	b := startUIBrowser(t, bin, proxy)
	b.size(1280, 900)
	b.navigate("https://net.example.test/")
	code := b.waitText(t, regexp.MustCompile(`sudo ento admin ui ([A-Z0-9]{4}-[A-Z0-9]{4})`), 20*time.Second)
	if st := approve(t, admin, code); st != 200 {
		t.Fatalf("approve the page: HTTP %d", st)
	}
	b.waitJS(t, `!document.getElementById("app").hidden && getComputedStyle(document.getElementById("app")).display !== "none" && document.getElementById("nav").offsetParent !== null`, 20*time.Second)
	b.countFetches()

	type result struct {
		Page, Width, Theme string
		Millis             int64
		Overflow           []string
	}
	var results []result
	pages := []string{"overview", "people", "devices", "groups", "access", "routes", "names", "links", "activity"}
	budget := 3 * time.Second
	for _, w := range []struct {
		name string
		w, h int
	}{{"desktop", 1280, 900}, {"phone", 390, 844}} {
		b.size(w.w, w.h)
		for _, theme := range []string{"light", "dark"} {
			b.theme(theme)
			for _, p := range pages {
				took := b.open(t, p)
				over := b.overflow()
				results = append(results, result{p, w.name, theme, took.Milliseconds(), over})
				b.screenshot(t, filepath.Join(shots, fmt.Sprintf("%s-%s-%s.png", p, w.name, theme)))
				if took > budget {
					t.Errorf("%s (%s, %s): %v to load, more than %v", p, w.name, theme, took, budget)
				}
				if len(over) > 0 {
					t.Errorf("%s (%s, %s): sticks out sideways: %s", p, w.name, theme, strings.Join(over, "; "))
				}
			}
		}
	}
	// The detail panels of a person, a device and a group, at both widths.
	for _, w := range []struct {
		name string
		w, h int
	}{{"desktop", 1280, 900}, {"phone", 390, 844}} {
		b.size(w.w, w.h)
		b.theme("light")
		for _, d := range []struct{ page, sel, name string }{
			{"people", `#people-table tbody tr`, "people"},
			{"devices", `#device-table tbody tr:nth-child(2)`, "devices"},
			{"devices", `#device-table tbody tr:first-child`, "control"},
			{"groups", `#group-list > *`, "groups"},
		} {
			b.open(t, d.page)
			if !b.clickFirst(d.sel) {
				t.Logf("%s: no item to open (%s)", d.page, d.sel)
				continue
			}
			time.Sleep(700 * time.Millisecond)
			over := b.overflow()
			results = append(results, result{d.name + "-detail", w.name, "light", 0, over})
			b.screenshot(t, filepath.Join(shots, fmt.Sprintf("%s-detail-%s.png", d.name, w.name)))
			if len(over) > 0 {
				t.Errorf("%s detail (%s): sticks out sideways: %s", d.name, w.name, strings.Join(over, "; "))
			}
		}
	}
	// The network's control nodes are among its devices, first, with a panel of their own.
	b.size(1280, 900)
	b.open(t, "devices")
	if first, _ := b.eval(`document.querySelector("#device-table tbody tr").innerText`).(string); !strings.Contains(first, "c1") || !strings.Contains(first, "Control node") {
		t.Errorf("the first row is not the control node: %q", first)
	}
	b.clickFirst(`#device-table tbody tr:first-child`)
	if side, _ := b.eval(`document.getElementById("device-detail").innerText`).(string); !strings.Contains(side, "One of this network's own servers") {
		t.Errorf("the control node's panel: %q", side)
	}
	var rep strings.Builder
	fmt.Fprintf(&rep, "# Admin interface at scale\n\nData: %v\n\n| Page | Width | Theme | Load (ms) | Sticks out |\n|---|---|---|---|---|\n", counts)
	for _, r := range results {
		fmt.Fprintf(&rep, "| %s | %s | %s | %d | %s |\n", r.Page, r.Width, r.Theme, r.Millis, strings.Join(r.Overflow, "; "))
	}
	os.WriteFile(filepath.Join(shots, "report.md"), []byte(rep.String()), 0o644)
	t.Logf("screenshots and report in %s", shots)
}

// startScaleUI starts a control node that is its network's identity provider (people in its own
// database) and serves the admin interface, and enrolls an admin device signed in as an admin.
func startScaleUI(t *testing.T, ctx context.Context) (*Server, store.Store, *testClient) {
	t.Helper()
	certFile, keyFile, _ := selfSigned(t, t.TempDir(), "net.example.test", testIDName)
	space, _ := ipam.New(netip.MustParsePrefix("100.64.0.0/16"))
	mem := store.NewMemory(space)
	key, _ := wgtypes.GeneratePrivateKey()
	signing, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	port := freeUDPPort(t)
	srv, err := Start(ctx, Config{Name: "c1", PrivateKey: key, ListenPort: port, Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Space: space, Store: mem, Logf: func(string, ...any) {}, Version: "test",
		ID: &IDConfig{Name: testIDName, Title: "Example", Key: signing, Disabled: true},
		OIDC: &OIDCConfig{Issuer: IDIssuer(testIDName), ClientID: "ento", ClientSecret: IDClientSecret(signing, "ento"),
			ApproveGroups: []string{"staff"}, AdminGroups: []string{"admins"}, TokenKey: make([]byte, 32)},
		AdminUI: "net.example.test", AdminUICert: certFile, AdminUIKey: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	tok, _, _ := IssueToken(ctx, mem, TokenOptions{Approve: true, Admin: true})
	admin, _ := enroll(t, tok, "admin-laptop")
	signInRoles(t, mem)
	return srv, mem, admin
}

// fillAtScale gives the network 100+ of every kind of item, with long names here and there.
func fillAtScale(t *testing.T, ctx context.Context, srv *Server, st store.Store) map[string]int {
	t.Helper()
	now := time.Now()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	teams := make([]string, 0, 120)
	for i := 1; i <= 120; i++ {
		name := fmt.Sprintf("team-%03d", i)
		if i%17 == 0 {
			name = fmt.Sprintf("customer-success-and-onboarding-%03d", i)
		}
		teams = append(teams, name)
	}
	must(srv.people.ensureGroups(ctx, append([]string{"staff", "admins", "operators"}, teams...)))
	first := []string{"Ana", "Bogdan", "Cristina", "Dan", "Elena", "Florin", "Gabriela", "Horia", "Ioana", "Mihai",
		"Maximilian-Alexandru", "Zoë"}
	last := []string{"Popescu", "Ionescu", "Dumitrescu", "Stan", "Constantinescu-Vlădescu", "Radu", "Marin", "Tudor"}
	for i := 1; i <= 150; i++ {
		g, f := first[i%len(first)], last[i%len(last)]
		groups := []string{"staff", teams[i%len(teams)], teams[(i*7)%len(teams)]}
		if i%25 == 0 {
			groups = append(groups, "admins")
		}
		_, err := srv.people.create(ctx, api.NewPersonRequest{Email: fmt.Sprintf("%s.%s.%d@example.com", strings.ToLower(g), strings.ToLower(f), i),
			GivenName: g, FamilyName: f, Groups: groups})
		must(err)
	}
	fleets := make([]string, 0, 110)
	for i := 1; i <= 110; i++ {
		fleets = append(fleets, fmt.Sprintf("device:fleet-%03d", i))
	}
	osNames := []string{"linux", "windows", "darwin", "android"}
	var gateways []string
	on := true
	for i := 1; i <= 160; i++ {
		temp, _ := wgtypes.GeneratePrivateKey()
		k, _ := wgtypes.GeneratePrivateKey()
		name := fmt.Sprintf("laptop-%03d", i)
		if i%3 == 0 {
			name = fmt.Sprintf("srv-%03d", i)
		}
		if i%23 == 0 {
			name = fmt.Sprintf("warehouse-scanner-building-b-%03d", i)
		}
		tok, err := st.CreateToken(ctx, store.Token{PublicKey: temp.PublicKey(), Name: name, Approve: i%9 != 0,
			Groups: []string{fleets[i%len(fleets)], fleets[(i*3)%len(fleets)]}, ExpiresAt: now.Add(time.Hour)})
		must(err)
		p, err := st.Redeem(ctx, tok.TempAddress, k.PublicKey(), name, osNames[i%len(osNames)], now, nil)
		must(err)
		if i%2 == 0 {
			sub := fmt.Sprintf("sub-%d", i)
			_, err = st.UpdatePeer(ctx, p.ID, store.PeerUpdate{User: &sub, LoginAt: &now, PersonActive: &on, PersonApproved: &on})
			must(err)
		}
		if i%3 != 0 {
			_, _, err = st.ObservePeer(ctx, k.PublicKey(), fmt.Sprintf("203.0.113.%d:51820", i%250+1), now.Add(-time.Duration(i)*time.Minute))
			must(err)
		}
		if i <= 12 {
			gateways = append(gateways, name)
		}
	}
	for i := 1; i <= 110; i++ {
		var err error
		if i%2 == 0 {
			_, _, err = IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{fleets[i%len(fleets)]}, Name: fmt.Sprintf("new-%03d", i), TTL: 24 * time.Hour})
		} else {
			_, _, err = IssueToken(ctx, st, TokenOptions{Groups: []string{teams[i%len(teams)]}, TTL: 7 * 24 * time.Hour})
		}
		must(err)
	}
	for i := 1; i <= 110; i++ {
		_, err := st.AddPostureCheck(ctx, store.PostureCheck{Name: fmt.Sprintf("check-%03d", i), DiskEncryption: i%2 == 0, Firewall: true,
			SecureBoot: i%3 == 0, MinOS: map[string]string{"linux": "6.12", "windows": "10.0.26100"}, MaxAge: 30 * 24 * time.Hour, CreatedAt: now})
		must(err)
	}
	ports := [][]string{nil, {"tcp/22"}, {"tcp/443", "tcp/80"}, {"udp/53", "tcp/53", "icmp"}, {"tcp/5432"}, {"tcp/8000-8999", "udp/51820", "tcp/3389", "icmp"}}
	for i := 1; i <= 160; i++ {
		src, dst := "group:"+teams[i%len(teams)], fleets[(i*5)%len(fleets)]
		if i%4 == 0 {
			src = fleets[i%len(fleets)]
		}
		_, err := st.AddPolicy(ctx, store.Policy{Source: src, Destination: dst, Ports: ports[i%len(ports)], OneWay: true})
		must(err)
	}
	for i := 1; i <= 105; i++ {
		pfx := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16)
		must(st.AddRoute(ctx, store.Route{Name: fmt.Sprintf("office-%03d", i), Networks: []netip.Prefix{pfx}, Via: gateways[i%len(gateways)], CreatedAt: now}))
	}
	for i := 1; i <= 120; i++ {
		must(st.AddDNSRecord(ctx, store.DNSRecord{Name: fmt.Sprintf("printer-%03d.office", i), Address: netip.AddrFrom4([4]byte{10, byte(i), 1, 10}), CreatedAt: now}))
	}
	for i := 1; i <= 105; i++ {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		_, err := st.CreateLink(ctx, store.Link{Name: fmt.Sprintf("partner%03d", i), PrivateKey: priv, Groups: []string{teams[i%len(teams)]},
			Grant: []string{"support"}, TTL: 12 * time.Hour, CreatedAt: now})
		must(err)
	}
	for i := 1; i <= 300; i++ {
		must(st.AddAudit(ctx, store.AuditEntry{At: now.Add(-time.Duration(i) * time.Minute), Node: "c1", Action: []string{"approve", "rename", "policy_add", "token_create", "suspend"}[i%5],
			Device: fmt.Sprintf("laptop-%03d", i%160+1), Person: "ana.popescu.1@example.com", From: "100.64.1.2", Target: fmt.Sprintf("laptop-%03d", (i*7)%160+1), Result: "ok"}))
	}
	return map[string]int{"people": 150, "people groups": 123, "devices": 161, "device groups": 110, "invitations": 110,
		"device checks": 110, "rules": 160, "routes": 105, "names": 120, "links": 105, "activity": 300}
}

// tunnelProxy is an HTTP proxy on loopback whose CONNECT requests go to the control node's port 443
// through the admin device's tunnel: the browser reaches the interface as the device does.
func tunnelProxy(t *testing.T, dev *testClient, ctl netip.Addr) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				up, err := dev.net.DialContextTCPAddrPort(context.Background(), netip.AddrPortFrom(ctl, 443))
				if err != nil {
					io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				done := make(chan struct{}, 2)
				go func() { io.Copy(up, c); done <- struct{}{} }()
				go func() { io.Copy(c, up); done <- struct{}{} }()
				<-done
			}()
		}
	}()
	return ln.Addr().String()
}

// uiBrowser drives one page of headless Chromium over the DevTools protocol.
type uiBrowser struct {
	t       *testing.T
	ws      *websocket.Conn
	session string
	mu      sync.Mutex
	next    int
	waiting map[int]chan map[string]any
}

func startUIBrowser(t *testing.T, bin, proxy string) *uiBrowser {
	t.Helper()
	cmd := exec.Command(bin, "--headless", "--no-sandbox", "--remote-debugging-port=0", "--remote-allow-origins=*",
		"--user-data-dir="+t.TempDir(), "--proxy-server=http://"+proxy, "--proxy-bypass-list=<-loopback>",
		"--ignore-certificate-errors", "--hide-scrollbars", "--font-render-hinting=none", "about:blank")
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	var wsURL string
	sc := bufio.NewScanner(stderr)
	for sc.Scan() {
		if u, ok := strings.CutPrefix(sc.Text(), "DevTools listening on "); ok {
			wsURL = u
			break
		}
	}
	go func() {
		for sc.Scan() {
		}
	}()
	if wsURL == "" {
		t.Fatal("the browser did not start")
	}
	ws, err := websocket.Dial(wsURL, "", "http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	ws.MaxPayloadBytes = 64 << 20
	b := &uiBrowser{t: t, ws: ws, waiting: map[int]chan map[string]any{}}
	go b.read()
	tgt := b.send("", "Target.createTarget", map[string]any{"url": "about:blank"})
	att := b.send("", "Target.attachToTarget", map[string]any{"targetId": tgt["targetId"], "flatten": true})
	b.session = att["sessionId"].(string)
	b.send(b.session, "Page.enable", nil)
	return b
}

func (b *uiBrowser) read() {
	for {
		var msg map[string]any
		if err := websocket.JSON.Receive(b.ws, &msg); err != nil {
			return
		}
		id, ok := msg["id"].(float64)
		if !ok {
			continue
		}
		b.mu.Lock()
		ch := b.waiting[int(id)]
		delete(b.waiting, int(id))
		b.mu.Unlock()
		if ch != nil {
			ch <- msg
		}
	}
}

func (b *uiBrowser) send(session, method string, params map[string]any) map[string]any {
	b.t.Helper()
	b.mu.Lock()
	b.next++
	id := b.next
	ch := make(chan map[string]any, 1)
	b.waiting[id] = ch
	b.mu.Unlock()
	if params == nil {
		params = map[string]any{}
	}
	msg := map[string]any{"id": id, "method": method, "params": params}
	if session != "" {
		msg["sessionId"] = session
	}
	if err := websocket.JSON.Send(b.ws, msg); err != nil {
		b.t.Fatal(err)
	}
	select {
	case r := <-ch:
		if e, ok := r["error"]; ok {
			b.t.Fatalf("%s: %v", method, e)
		}
		res, _ := r["result"].(map[string]any)
		return res
	case <-time.After(60 * time.Second):
		b.t.Fatalf("%s: no answer", method)
		return nil
	}
}

func (b *uiBrowser) eval(js string) any {
	b.t.Helper()
	r := b.send(b.session, "Runtime.evaluate", map[string]any{"expression": js, "returnByValue": true, "awaitPromise": true})
	if ex, ok := r["exceptionDetails"]; ok {
		b.t.Fatalf("%s: %v", js, ex)
	}
	v, _ := r["result"].(map[string]any)
	return v["value"]
}

func (b *uiBrowser) navigate(url string) {
	b.send(b.session, "Page.navigate", map[string]any{"url": url})
}

func (b *uiBrowser) size(w, h int) {
	b.send(b.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": w, "height": h, "deviceScaleFactor": 1, "mobile": w < 600})
}

func (b *uiBrowser) theme(name string) {
	b.send(b.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]any{{"name": "prefers-color-scheme", "value": name}}})
}

func (b *uiBrowser) waitJS(t *testing.T, cond string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if v, _ := b.eval(cond).(bool); v {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("not within %v: %s\n%s", d, cond, b.eval(`document.body ? document.body.innerText.slice(0, 2000) : ""`))
}

func (b *uiBrowser) waitText(t *testing.T, re *regexp.Regexp, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s, _ := b.eval(`document.body ? document.body.innerText : ""`).(string)
		if m := re.FindStringSubmatch(s); m != nil {
			return m[1]
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no %s within %v", re, d)
	return ""
}

// countFetches counts the page's requests in flight, so a page is loaded once none is left.
func (b *uiBrowser) countFetches() {
	b.eval(`(() => { if (window.__inflight !== undefined) return; window.__inflight = 0; const f = window.fetch;
	  window.fetch = (...a) => { window.__inflight++; return f(...a).finally(() => { window.__inflight--; }); }; })()`)
}

// open shows a page and returns how long it took until its requests were answered and it was drawn.
func (b *uiBrowser) open(t *testing.T, page string) time.Duration {
	t.Helper()
	start := time.Now()
	b.eval(fmt.Sprintf(`location.hash = "#%s"; new Promise(r => setTimeout(r, 30))`, page))
	deadline := start.Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if v, _ := b.eval(`window.__inflight === 0`).(bool); v {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	b.eval(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))`)
	return time.Since(start)
}

// overflow names what sticks out of the window sideways: the page itself, or elements whose right
// edge is past it (inside an element that scrolls sideways is fine).
func (b *uiBrowser) overflow() []string {
	v := b.eval(`(() => {
	  const out = [], w = document.documentElement.clientWidth;
	  if (document.documentElement.scrollWidth > w + 1) {
	    let widest = null;
	    for (const e of document.querySelectorAll("body *")) { if (e.offsetWidth > w + 1 && (!widest || e.contains(widest) === false && widest.contains(e))) widest = e; }
	    const path = []; for (let e = widest; e && e !== document.body; e = e.parentElement) path.push((e.id ? "#" + e.id : e.tagName.toLowerCase() + (typeof e.className === "string" && e.className ? "." + e.className.split(" ").join(".") : "")) + ":" + e.offsetWidth);
	    out.push("page " + document.documentElement.scrollWidth + "px wide in " + w + " (" + path.join(" < ") + ")");
	  }
	  // Clipped when a scrolling or clipping ancestor is also in its chain of containing blocks: a
	  // positioned element escapes a scroller that is not one of them.
	  const scrolls = (e) => {
	    const blocks = new Set(); for (let p = e.offsetParent; p; p = p.offsetParent) blocks.add(p);
	    for (let p = e.parentElement; p; p = p.parentElement) {
	      const s = getComputedStyle(p).overflowX;
	      if ((s === "auto" || s === "scroll" || s === "hidden" || s === "clip") && (getComputedStyle(e).position !== "absolute" || blocks.has(p) || getComputedStyle(p).position !== "static")) return true;
	    }
	    return false;
	  };
	  for (const e of document.querySelectorAll("body *")) {
	    const r = e.getBoundingClientRect();
	    if (r.width === 0 || r.height === 0 || getComputedStyle(e).visibility === "hidden") continue;
	    if (r.right > w + 1 && !scrolls(e)) out.push((e.id ? "#" + e.id : e.tagName.toLowerCase() + (e.className && typeof e.className === "string" ? "." + e.className.split(" ")[0] : "")) + " to " + Math.round(r.right) + "px");
	    if (out.length > 6) break;
	  }
	  return out;
	})()`)
	var out []string
	if xs, ok := v.([]any); ok {
		for _, x := range xs {
			out = append(out, fmt.Sprint(x))
		}
	}
	sort.Strings(out)
	return out
}

func (b *uiBrowser) clickFirst(sel string) bool {
	v, _ := b.eval(fmt.Sprintf(`(() => { const e = document.querySelector(%q); if (!e) return false; e.click(); return true; })()`, sel)).(bool)
	return v
}

// screenshot saves the page down to 6000 pixels, and its first screen as <name>-top.png.
func (b *uiBrowser) screenshot(t *testing.T, path string) {
	t.Helper()
	b.shoot(t, path, `Math.min(document.documentElement.scrollHeight, 6000)`)
	b.shoot(t, strings.TrimSuffix(path, ".png")+"-top.png", `window.innerHeight`)
}

func (b *uiBrowser) shoot(t *testing.T, path, height string) {
	t.Helper()
	r := b.send(b.session, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": true,
		"clip": map[string]any{"x": 0, "y": 0, "width": b.eval(`document.documentElement.clientWidth`), "height": b.eval(height), "scale": 1}})
	data, err := base64.StdEncoding.DecodeString(r["data"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
