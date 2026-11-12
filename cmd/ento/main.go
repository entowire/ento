// Command ento is the single binary of ento: control node, agent and administration CLI.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/agent"
	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/attest"
	"entowire.com/ento/internal/control"
	"entowire.com/ento/internal/credential"
	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/ports"
	"entowire.com/ento/internal/store"
	"entowire.com/ento/internal/token"
	"entowire.com/ento/internal/update"
)

// version is set at build time (scripts/build.sh).
var version = "dev"

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, shortUsage)
		os.Exit(2)
	}
	// `ento agent` (and admin, control, update) alone, or with only --help: that part of the help.
	if t, ok := helpTopics[os.Args[1]]; ok && isHelp(os.Args[2:]) {
		fmt.Fprint(os.Stderr, usageHeader+strings.TrimRight(t, "\n")+"\n")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "control":
		err = controlCmd(ctx, args)
	case "agent":
		err = agentCmd(ctx, args)
	case "login", "logout", "status", "whoami", "join", "leave", "up", "down", "exit":
		// The commands people use on their own device, without "agent" (0.58): the same commands.
		err = agentCmd(ctx, os.Args[1:])
	case "admin":
		err = adminCmd(ctx, args)
	case "update":
		err = updateCmd(ctx, args)
	case "genkey":
		var k wgtypes.Key
		if k, err = wgtypes.GeneratePrivateKey(); err == nil {
			fmt.Println(k)
		}
	case "pubkey":
		err = pubkey()
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "-h", "--help":
		err = printHelp(os.Stdout, args)
	default:
		err = fmt.Errorf("unknown command %q", cmd)
	}
	var ec exitCode
	if errors.As(err, &ec) {
		if ec.msg != "" {
			fmt.Fprintln(os.Stderr, "ento: "+ec.msg)
		}
		os.Exit(ec.code)
	}
	if err != nil {
		log.Fatalf("ento: %v", err)
	}
}

// exitCode ends the program with a given status (`ento agent approve`).
type exitCode struct {
	code int
	msg  string
}

func (e exitCode) Error() string { return fmt.Sprintf("exit %d: %s", e.code, e.msg) }

func pubkey() error {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	k, err := wgtypes.ParseKey(strings.TrimSpace(line))
	if err != nil {
		return err
	}
	fmt.Println(k.PublicKey())
	return nil
}

func sub(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	return args[0], args[1:]
}

// --- control ------------------------------------------------------------------------------------

// storeNetwork is the network the command line last opened the database of: its audit line goes
// there too (cliAudit).
var storeNetwork string

func openStore(ctx context.Context, network string) (store.Store, ipam.Space, error) {
	storeNetwork = network
	prefix, err := netip.ParsePrefix(network)
	if err != nil {
		return nil, ipam.Space{}, err
	}
	space, err := ipam.New(prefix)
	if err != nil {
		return nil, ipam.Space{}, err
	}
	dsn := os.Getenv("ENTO_DATABASE_URL")
	if dsn == "" {
		return nil, space, errors.New("ENTO_DATABASE_URL is not set")
	}
	st, err := store.OpenPostgres(ctx, dsn, space)
	return st, space, err
}

func readKeyFile(path string) (wgtypes.Key, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return wgtypes.Key{}, err
	}
	return wgtypes.ParseKey(strings.TrimSpace(string(b)))
}

func controlCmd(ctx context.Context, args []string) (err error) {
	cmd, args := sub(args)
	// What changes the network's database without a control node in between leaves an audit line in
	// the system log (cliaudit), like the control nodes' own.
	switch cmd {
	case "token", "authority", "allow", "admin", "groups", "id-groups", "person", "sso-forget":
		all := append([]string{cmd}, args...)
		defer func() { cliAudit(all, err) }()
	}
	switch cmd {
	case "run":
		fs := flag.NewFlagSet("control run", flag.ExitOnError)
		name := fs.String("name", "", "unique name of this control node")
		keyFile := fs.String("key-file", "", "file holding this node's WireGuard private key")
		port := fs.Int("listen-port", 51821, "WireGuard UDP port")
		endpoint := fs.String("endpoint", "", "public host:port agents use to reach this node")
		network := fs.String("network", "100.64.0.0/16", "overlay network (IPv4 /16)")
		oidcIssuer := fs.String("oidc-issuer", "", "enable SSO device login with this OpenID Connect issuer (client secret in ENTO_OIDC_CLIENT_SECRET; with ENTO_OIDC_TOKEN_KEY, 32 bytes in base64 and the same on every control node, refresh tokens are kept encrypted and checked every --oidc-refresh-interval, so that users disabled or deleted there lose access within minutes)")
		oidcRefresh := fs.Duration("oidc-refresh-interval", 2*time.Minute, "with ENTO_OIDC_TOKEN_KEY: how often each signed-in device's user is checked with the identity provider")
		oidcClient := fs.String("oidc-client-id", "ento", "OIDC client ID (confidential, device authorization grant enabled)")
		oidcConnect := fs.String("oidc-connect-to", "", "comma-separated host:port to dial instead of the issuer's host")
		oidcGroups := fs.String("oidc-groups-claim", "groups", "ID token claim listing the user's groups")
		oidcApps := fs.String("oidc-app-redirects", "", "comma-separated addresses that apps on devices catch (RFC 8252, e.g. com.entowire.ento://signed-in), registered with the identity provider for --oidc-client: an app starting a sign-in with one of them gets an ordinary sign-in that returns to it, with no code to type")
		oidcRefusals := fs.String("oidc-refusals", "400:invalid_grant", "comma-separated STATUS:ERROR answers of the token endpoint that withdraw a user's access at a refresh (RFC 6749's invalid_grant; Rauthy also needs 401:Disabled,404:NotFound); any other failure counts as the provider failing and cuts nothing")
		oidcApprove := fs.String("oidc-approve-groups", "", "comma-separated groups whose members' devices are approved")
		oidcAdmin := fs.String("oidc-admin-groups", "", "comma-separated groups whose members get admin devices")
		oidcOperator := fs.String("oidc-operator-groups", "", "comma-separated groups whose members get operator devices (administration limited to what can be undone)")
		linkForwards := fs.String("link-forwards", "", "services of this network that devices make reachable inside the namespaces of their linked networks: comma-separated NAME:PORT=TARGET[+TARGET...], targets address:port in this network")
		hosts := fs.String("hosts", "", "comma-separated name=address pairs of the network's services, published to devices without DNS for it (linked networks)")
		attestRevocations := fs.String("attestation-revocations", "", "where the list of revoked Android attestation certificates is fetched once a phone sends an attestation (default Google's, "+attest.DefaultRevocationsURL+"; off: not checked, which keys leaked from phones make unsafe)")
		androidApps := fs.String("android-apps", "", "comma-separated PACKAGE:SHA256 (the signing certificate's): the only apps whose attestations count (default: any app; the attestation must still be made for the device's key)")
		serviceNames := fs.String("service-names", "", "comma-separated names of the network's services that point at addresses inside it (e.g. chat.example.com): the node resolves them and every device answers them itself, so DNS that drops answers pointing at private or shared addresses does not hide them")
		forwardList := fs.String("forward", "", "services passed through on the node's overlay port 443 by TLS server name, for the devices rules let reach service:NAME (0.53; the first time a node forwards one it adds the rule that keeps who reached it before): comma-separated NAME=HOST:PORT[+HOST:PORT...], tried in order; devices resolve NAME to the control nodes")
		forwardPeopleList := fs.String("forward-people", "", "forwarded services (--forward) that only devices with a person signed in in one of these roles reach, by the person's own groups (not the device's), checked while each connection lasts: comma-separated NAME=ROLE[+ROLE...], roles admin, operator, viewer")
		recordDomain := fs.String("record-domain", "", "the domain whose network record (TXT _ento.<domain>, what ento admin record prints) names the control nodes: devices that reach none of them look there for their new endpoints; the node checks hourly that it is named")
		dnsDomain := fs.String("dns-domain", "", "internal DNS: devices answer names in this domain (e.g. example.internal): each other's names, and those administrators add (ento admin dns); the same on every control node")
		sessionIdle := fs.Duration("session-idle", 8*time.Hour, "with SSO: a device's person layer closes after this long without the person's traffic over the tunnel (0: never); its machine layer stays")
		sessionMax := fs.Duration("session-max", 0, "with SSO: a device's person layer closes this long after it opened, even in use (0, the default: never)")
		reopenServices := fs.String("reopen-services", strings.Join(control.DefaultReopenServices, ","), "sign-ins (PAM services) whose approval on another of the person's devices reopens a device's person layer, within 7 days of their last full sign-in on it")
		updatesDir := fs.String("updates-dir", "", "offer the network's devices the release this node runs (0.37): its files are downloaded here, checked with this binary's keys, and served to enrolled devices; the network's policy (ento admin updates) decides who is offered it. Empty: no updates offered")
		releases := fs.String("releases", "", "where releases are fetched from (default "+update.DefaultReleases+")")
		updatesExcept := fs.String("updates-except", "", "a group never offered an update (devices updated otherwise, such as servers updated by their deployments)")
		cloneResponse := fs.String("clone-response", control.CloneAuto, "a check-in suspecting a copied device identity: auto (suspend devices signed in to a person, report others), suspend (all), report (none)")
		adminUI := fs.String("admin-ui", "", "serve the admin web interface under this name on port 443 of the node's overlay address (admin devices only)")
		adminUICert := fs.String("admin-ui-cert", "", "certificate (PEM, with chain) for --admin-ui; read again when it changes")
		adminUIKey := fs.String("admin-ui-key", "", "private key (PEM) for --admin-ui")
		signInClient := fs.String("device-sign-in-client", "", "with --admin-ui: be an OpenID Connect provider at https://<admin-ui>/device for this client (typically your identity provider, brokering to it), signing in the person of the calling device while their session on it is open and recent; client secret in ENTO_SIGNIN_CLIENT_SECRET, signing key (P-256, DER in base64, the same on every control node) in ENTO_SIGNIN_KEY")
		signInRedirect := fs.String("device-sign-in-redirect", "", "comma-separated redirect URIs of the --device-sign-in-client (exact matches)")
		adminGroups := fs.String("admin-groups", "", "comma-separated groups whose devices are admins (default: --oidc-admin-groups, else admins)")
		operatorGroups := fs.String("operator-groups", "", "comma-separated groups whose devices are operators (default: --oidc-operator-groups, else operators)")
		viewerGroups := fs.String("viewer-groups", "", "comma-separated groups whose devices and people may only look at the administration (default: viewers)")
		noGateways := fs.String("no-gateways", "", "comma-separated groups whose devices are never a route's gateway or an exit (such routes are refused, and existing ones never used)")
		signInIdle := fs.Duration("device-sign-in-idle", control.DefaultSignInIdle, "a device stops vouching for its person this long after it last signed them in or their session on it opened")
		idName := fs.String("id", "", "be the network's identity provider under this name (e.g. id.example.com) on port 443 of the node's overlay address: people sign in with passkeys, kept in the network's database; signing key (P-256, DER in base64, the same on every control node) in ENTO_ID_KEY. Without --oidc-issuer the control nodes sign their devices in with it; the dashboard manages its people")
		idCert := fs.String("id-cert", "", "certificate (PEM, with chain) for --id; read again when it changes")
		idCertKey := fs.String("id-cert-key", "", "private key (PEM) of --id-cert")
		idTitle := fs.String("id-title", "", "the network's name, shown on the sign-in pages and by passkey managers (default: --id)")
		idListen := fs.String("id-listen", "", "with --id: also serve it on this host address (host:port, TLS with --id-cert), for services beside the control nodes that are no devices of the network; never a public address")
		idClients := fs.String("id-clients", "", "a JSON file of other applications that sign people in with --id: [{\"id\", \"name\", \"secret\", \"redirect_uris\": [...], \"device_grant\"}]")
		_ = fs.Parse(args)
		if *name == "" || *keyFile == "" || *endpoint == "" {
			return errors.New("--name, --key-file and --endpoint are required")
		}
		if *adminUI != "" && (*adminUICert == "" || *adminUIKey == "") {
			return errors.New("--admin-ui needs --admin-ui-cert and --admin-ui-key")
		}
		key, err := readKeyFile(*keyFile)
		if err != nil {
			return fmt.Errorf("key file: %w", err)
		}
		st, space, err := openStore(ctx, *network)
		if err != nil {
			return err
		}
		defer st.Close()
		var changes <-chan struct{}
		if pg, ok := st.(*store.Postgres); ok {
			changes = pg.Listen(ctx, log.Printf)
		}
		forwards, err := control.ParseLinkForwards(*linkForwards, space.Prefix)
		if err != nil {
			return err
		}
		var idCfg *control.IDConfig
		if *idName != "" {
			if idCfg, err = idConfig(*idName, *idTitle, *idCert, *idCertKey, *idClients); err != nil {
				return err
			}
			idCfg.Listen = *idListen
		}
		var oidc *control.OIDCConfig
		ownID := idCfg != nil && (*oidcIssuer == "" || *oidcIssuer == control.IDIssuer(idCfg.Name))
		if ownID {
			*oidcIssuer = control.IDIssuer(idCfg.Name)
		}
		if *oidcIssuer != "" {
			secret := os.Getenv("ENTO_OIDC_CLIENT_SECRET")
			if ownID {
				secret = control.IDClientSecret(idCfg.Key, *oidcClient)
			}
			if secret == "" {
				return errors.New("--oidc-issuer needs ENTO_OIDC_CLIENT_SECRET")
			}
			oidc = &control.OIDCConfig{Issuer: *oidcIssuer, ClientID: *oidcClient, ClientSecret: secret,
				ConnectTo: splitList(*oidcConnect), GroupsClaim: *oidcGroups,
				ApproveGroups: splitList(*oidcApprove), AdminGroups: splitList(*oidcAdmin),
				OperatorGroups: splitList(*oidcOperator), RefreshInterval: *oidcRefresh, AppRedirects: splitList(*oidcApps)}
			if oidc.Refusals, err = control.ParseRefusals(*oidcRefusals); err != nil {
				return fmt.Errorf("--oidc-refusals: %w", err)
			}
			if k := os.Getenv("ENTO_OIDC_TOKEN_KEY"); k != "" {
				key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k))
				if err != nil || len(key) != 32 {
					return errors.New("ENTO_OIDC_TOKEN_KEY must be 32 bytes in base64 (openssl rand -base64 32)")
				}
				oidc.TokenKey = key
			}
			if *oidcRefresh < 30*time.Second {
				return errors.New("--oidc-refresh-interval must be at least 30s")
			}
		}
		var signIn *control.SignInConfig
		if *signInClient != "" {
			if *adminUI == "" {
				return errors.New("--device-sign-in-client needs --admin-ui")
			}
			secret := os.Getenv("ENTO_SIGNIN_CLIENT_SECRET")
			if len(secret) < 32 {
				return errors.New("--device-sign-in-client needs ENTO_SIGNIN_CLIENT_SECRET (at least 32 characters)")
			}
			key, err := control.ParseSignInKey(os.Getenv("ENTO_SIGNIN_KEY"))
			if err != nil {
				return fmt.Errorf("ENTO_SIGNIN_KEY: %w (openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform DER | base64 -w0)", err)
			}
			redirects := splitList(*signInRedirect)
			if len(redirects) == 0 {
				return errors.New("--device-sign-in-client needs --device-sign-in-redirect")
			}
			for _, u := range redirects {
				if !strings.HasPrefix(u, "https://") {
					return fmt.Errorf("--device-sign-in-redirect: %s is not an https:// address", u)
				}
			}
			if *signInIdle < time.Minute {
				return errors.New("--device-sign-in-idle must be at least 1m")
			}
			signIn = &control.SignInConfig{ClientID: *signInClient, ClientSecret: secret, RedirectURIs: redirects, Key: key, Idle: *signInIdle}
		}
		if *cloneResponse != control.CloneAuto && *cloneResponse != control.CloneSuspend && *cloneResponse != control.CloneReport {
			return fmt.Errorf("--clone-response: auto, suspend or report")
		}
		domain := ""
		if *dnsDomain != "" {
			if domain, err = control.CheckDNSDomain(*dnsDomain); err != nil {
				return fmt.Errorf("--dns-domain: %w", err)
			}
		}
		named, err := control.ParseForwards(*forwardList)
		if err != nil {
			return err
		}
		forwardPeople, err := control.ParseForwardPeople(*forwardPeopleList, named)
		if err != nil {
			return err
		}
		recDomain := ""
		if *recordDomain != "" {
			if recDomain, err = control.CheckDNSDomain(*recordDomain); err != nil {
				return fmt.Errorf("--record-domain: %w", err)
			}
		}
		var services []string
		for _, n := range splitList(*serviceNames) {
			d, err := control.CheckDNSDomain(n)
			if err != nil {
				return fmt.Errorf("--service-names: %w", err)
			}
			services = append(services, d)
		}
		apps, err := attest.ParseApps(*androidApps)
		if err != nil {
			return fmt.Errorf("--android-apps: %w", err)
		}
		if *attestRevocations != "" && *attestRevocations != "off" && !strings.HasPrefix(*attestRevocations, "https://") {
			return errors.New("--attestation-revocations: an https:// address, or off")
		}
		srv, err := control.Start(ctx, control.Config{Name: *name, PrivateKey: key, ListenPort: *port, DNSDomain: domain, RecordDomain: recDomain, Forwards: named, ForwardPeople: forwardPeople,
			AttestationRevocations: *attestRevocations, AndroidApps: apps, ServiceNames: services,
			Endpoint: *endpoint, Space: space, Store: st, Changes: changes, OIDC: oidc, NoGateways: splitList(*noGateways), AdminGroups: splitList(*adminGroups), OperatorGroups: splitList(*operatorGroups), ViewerGroups: splitList(*viewerGroups),
			SessionIdle: *sessionIdle, SessionMax: *sessionMax, ReopenServices: splitList(*reopenServices), Hosts: parseHosts(*hosts), LinkForwards: forwards,
			AdminUI: *adminUI, AdminUICert: *adminUICert, AdminUIKey: *adminUIKey, SignIn: signIn, ID: idCfg, Version: version, CloneResponse: *cloneResponse,
			UpdatesDir: *updatesDir, Releases: *releases, UpdatesExcept: *updatesExcept})
		if err != nil {
			return err
		}
		<-ctx.Done()
		srv.Close()
		return nil

	case "token":
		fs := flag.NewFlagSet("control token", flag.ExitOnError)
		network := fs.String("network", "100.64.0.0/16", "overlay network (IPv4 /16)")
		opts := tokenFlags(fs)
		out := fs.String("out", "", "write the token to this file (mode 0600) instead of stdout")
		person := fs.String("person", "", "an invitation of the account with this address in the control nodes' own sign-in (not set up yet): the device that redeems the token is invited for it, and its first sign-in sets the account up and signs in with it, in one go")
		_ = fs.Parse(args)
		o, q := opts()
		if err := q.check(o.Words, true); err != nil {
			return err
		}
		st, space, err := openStore(ctx, *network)
		if err != nil {
			return err
		}
		defer st.Close()
		o.Network = space.Prefix
		tok, t, err := control.IssueToken(ctx, st, o)
		if err != nil {
			return err
		}
		if *person != "" {
			if err := control.InviteWithToken(ctx, st, t, *person); err != nil {
				st.DeleteToken(ctx, t.ID)
				return err
			}
		}
		if o.Words {
			rec, err := control.NetworkRecord(ctx, st, space.Prefix)
			if err != nil {
				return err
			}
			return emitWords(tok, rec.Fingerprint(), t.ExpiresAt, *out, q)
		}
		return emitToken(tok, t.ExpiresAt, *out)

	case "record":
		fs := flag.NewFlagSet("control record", flag.ExitOnError)
		network := fs.String("network", "100.64.0.0/16", "overlay network (IPv4 /16)")
		_ = fs.Parse(args)
		st, space, err := openStore(ctx, *network)
		if err != nil {
			return err
		}
		defer st.Close()
		rec, err := control.NetworkRecord(ctx, st, space.Prefix)
		if err != nil {
			return err
		}
		fmt.Println(rec.String())
		fmt.Fprintf(os.Stderr, "publish as the TXT record %s.<domain>; fingerprint %s\n", token.RecordName, rec.Fingerprint())
		return nil

	case "authority":
		fs := flag.NewFlagSet("control authority", flag.ExitOnError)
		network := fs.String("network", "100.64.0.0/16", "overlay network (IPv4 /16)")
		key := fs.String("key", "", "the authority's public key (entoa1:...)")
		groups := fs.String("groups", "", "comma-separated groups the authority may assign")
		maxTTL := fs.Duration("max-ttl", 12*time.Hour, "longest approval a single credential may give")
		maxDevices := fs.Int("max-devices", 0, "how many of its devices may be in the network at a time (0: no limit)")
		op, rest := sub(args)
		name, flags := sub(rest)
		_ = fs.Parse(flags)
		st, _, err := openStore(ctx, *network)
		if err != nil {
			return err
		}
		defer st.Close()
		switch op {
		case "add":
			pub, err := credential.ParsePublicKey(*key)
			if err != nil {
				return err
			}
			tok, err := control.IssueAuthorityToken(ctx, st, store.Authority{Name: name, PublicKey: pub,
				Groups: splitList(*groups), MaxTTL: *maxTTL, MaxDevices: *maxDevices})
			if err != nil {
				return err
			}
			fmt.Println(tok)
			return nil
		case "token":
			tok, err := control.RotateAuthorityToken(ctx, st, name)
			if err != nil {
				return err
			}
			fmt.Println(tok)
			return nil
		case "delete":
			return st.DeleteAuthority(ctx, name)
		}
		return errors.New("usage: ento control authority add|token|delete NAME [flags]")

	case "allow":
		// A policy goes one way (0.52), on every port unless --ports says otherwise; for an existing
		// one, only what is given changes (so setup steps can run again).
		rules, rest, err := ruleFlags(args)
		if err != nil {
			return err
		}
		fs := flag.NewFlagSet("control allow", flag.ExitOnError)
		network := fs.String("network", "100.64.0.0/16", "overlay network (IPv4 /16)")
		_ = fs.Parse(rest)
		if fs.NArg() != 2 {
			return errors.New("usage: ento control allow [--network N] [--ports RULES|all] SOURCE DESTINATION (SOURCE opens, DESTINATION answers)")
		}
		if slices.Equal(rules, []string{"all"}) {
			rules = []string{}
		}
		st, _, err := openStore(ctx, *network)
		if err != nil {
			return err
		}
		defer st.Close()
		want := store.Policy{Source: fs.Arg(0), Destination: fs.Arg(1), OneWay: true, Ports: rules}
		got, err := st.AddPolicy(ctx, want)
		if err != nil {
			return err
		}
		pr := got.Ports
		if rules != nil {
			pr = rules
		}
		if !got.OneWay || !slices.Equal(pr, got.Ports) && len(pr)+len(got.Ports) > 0 {
			_, err = st.SetPolicyRules(ctx, got.ID, true, pr)
		}
		return err

	case "admin":
		fs := flag.NewFlagSet("control admin", flag.ExitOnError)
		network := fs.String("network", "100.64.0.0/16", "overlay network (IPv4 /16)")
		off := fs.Bool("off", false, "take the administrator rights away instead")
		_ = fs.Parse(args)
		if fs.NArg() != 1 {
			return errors.New("usage: ento control admin [--network N] [--off] NAME")
		}
		st, _, err := openStore(ctx, *network)
		if err != nil {
			return err
		}
		defer st.Close()
		p, err := setAdmin(ctx, st, fs.Arg(0), !*off)
		if err != nil {
			return err
		}
		// The device's group (0.54): it administers only with a person in admins signed in on it.
		fmt.Printf("device %d %s: in admin=%v (approved=%v)\n", p.ID, p.Hostname, p.Machine.Admin, p.Approved)
		return nil
	case "groups":
		fs := flag.NewFlagSet("control groups", flag.ExitOnError)
		network := fs.String("network", "100.64.0.0/16", "overlay network (IPv4 /16)")
		_ = fs.Parse(args)
		if fs.NArg() < 2 {
			return errors.New("usage: ento control groups [--network N] NAME GROUP... (device groups, e.g. laptops)")
		}
		st, _, err := openStore(ctx, *network)
		if err != nil {
			return err
		}
		defer st.Close()
		p, err := setGroups(ctx, st, fs.Arg(0), fs.Args()[1:])
		if err != nil {
			return err
		}
		fmt.Printf("device %d %s: groups=%s (approved=%v)\n", p.ID, p.Hostname, strings.Join(p.Machine.Groups, ","), p.Approved)
		return nil
	case "id-groups":
		fs := flag.NewFlagSet("control id-groups", flag.ExitOnError)
		network := fs.String("network", "100.64.0.0/16", "overlay network (IPv4 /16)")
		_ = fs.Parse(args)
		if fs.NArg() == 0 {
			return errors.New("usage: ento control id-groups [--network N] GROUP... (people groups; device groups as device:NAME): made in the control nodes' own sign-in where missing")
		}
		st, _, err := openStore(ctx, *network)
		if err != nil {
			return err
		}
		defer st.Close()
		have, err := st.IDGroups(ctx)
		if err != nil {
			return err
		}
		for _, g := range fs.Args() {
			if slices.ContainsFunc(have, func(x store.IDGroup) bool { return x.Name == g }) {
				continue
			}
			kind := "people"
			if strings.HasPrefix(g, control.DevicePrefix) {
				kind = "devices"
			}
			if err := st.PutIDGroup(ctx, store.IDGroup{Name: g, Kind: kind}); err != nil {
				return err
			}
			fmt.Printf("group %s (%s) made\n", g, kind)
		}
		return nil
	case "sso-forget":
		// For a change of ENTO_OIDC_TOKEN_KEY on purpose: the stored refresh tokens cannot be read
		// with the new key, so they go, with the key's canary, and so do the rights of the people
		// they were for (signed out: they sign in again), rather than staying unchecked.
		fs := flag.NewFlagSet("control sso-forget", flag.ExitOnError)
		network := fs.String("network", "100.64.0.0/16", "overlay network (IPv4 /16)")
		_ = fs.Parse(args)
		if fs.NArg() != 0 {
			return errors.New("usage: ento control sso-forget [--network N] (before starting control nodes with a new ENTO_OIDC_TOKEN_KEY)")
		}
		st, _, err := openStore(ctx, *network)
		if err != nil {
			return err
		}
		defer st.Close()
		ids, err := st.ForgetSSOTokens(ctx)
		if err != nil {
			return err
		}
		off, none := false, []string{}
		for _, id := range ids {
			if _, err := st.UpdatePeer(ctx, id, store.PeerUpdate{PersonApproved: &off, PersonAdmin: &off, PersonOperator: &off,
				PersonGroups: &none, PersonActive: &off}); err != nil && !errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("sign out device %d: %w", id, err)
			}
		}
		fmt.Printf("refresh tokens forgotten: %d (those people are signed out); the token key's check starts again with the next control node\n", len(ids))
		return nil
	case "person":
		fs := flag.NewFlagSet("control person", flag.ExitOnError)
		network := fs.String("network", "100.64.0.0/16", "overlay network (IPv4 /16), with --id")
		groups := fs.String("groups", "", "comma-separated people groups, e.g. admins")
		idName := fs.String("id", "", "the control nodes' own identity provider (as ento control run --id; its signing key in ENTO_ID_KEY): the person is made in the network's database")
		noLink := fs.Bool("no-link", false, "with --id: no setup link (the person is invited with a device's words: ento control token --person)")
		reset := fs.Bool("reset", false, "with --id: a person who exists loses every way in first (passkeys, password, app) and gets a new link: recovery of an account whose person lost them")
		_ = fs.Parse(args)
		usage := errors.New("usage: ento control person --id NAME [--reset] [--groups G,...] EMAIL (signing key in ENTO_ID_KEY)")
		var p api.Person
		var link api.SetupLink
		var created bool
		switch {
		case fs.NArg() != 1:
			return usage
		case *idName != "":
			key, err := control.ParseSignInKey(os.Getenv("ENTO_ID_KEY"))
			if err != nil {
				return fmt.Errorf("ENTO_ID_KEY: %w", err)
			}
			st, _, err := openStore(ctx, *network)
			if err != nil {
				return err
			}
			defer st.Close()
			p, link, created, err = control.InvitePersonID(ctx, st, control.IDConfig{Name: *idName, Key: key}, fs.Arg(0), splitList(*groups), *reset, *noLink)
			if err != nil {
				return err
			}
		default:
			return usage
		}
		how := "made"
		if !created {
			how = "not set up yet, a new link"
		}
		if link.Link == "" {
			fmt.Printf("person %s (%s), groups %s\n", p.Email, strings.TrimSuffix(how, ", a new link"), strings.Join(p.Groups, ","))
			return nil
		}
		fmt.Printf("person %s (%s), groups %s\nsetup link (once, until %s): %s\n", p.Email, how, strings.Join(p.Groups, ","), link.ExpiresAt, link.Link)
		return nil
	}
	return errors.New("usage: ento control run|token|authority|allow|admin|groups|id-groups|person [flags]")
}

// idConfig reads the settings of the control nodes' own identity provider (ento control run --id).
func idConfig(name, title, cert, certKey, clientsFile string) (*control.IDConfig, error) {
	if cert == "" || certKey == "" {
		return nil, errors.New("--id needs --id-cert and --id-cert-key")
	}
	key, err := control.ParseSignInKey(os.Getenv("ENTO_ID_KEY"))
	if err != nil {
		return nil, fmt.Errorf("--id needs ENTO_ID_KEY: %w (openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform DER | base64 -w0)", err)
	}
	cfg := &control.IDConfig{Name: strings.ToLower(name), Title: title, Cert: cert, CertKey: certKey, Key: key}
	if clientsFile != "" {
		b, err := os.ReadFile(clientsFile)
		if err != nil {
			return nil, fmt.Errorf("--id-clients: %w", err)
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cfg.Clients); err != nil {
			return nil, fmt.Errorf("--id-clients %s: %w", clientsFile, err)
		}
	}
	return cfg, nil
}

// setAdmin gives the device named name administrator rights, or takes them away (bootstrap, straight
// in the database: for instance an operator's device in a network nobody administers yet).
func setAdmin(ctx context.Context, st store.Store, name string, admin bool) (store.Peer, error) {
	peers, err := st.Peers(ctx)
	if err != nil {
		return store.Peer{}, err
	}
	for _, p := range peers {
		if p.Hostname == name {
			// The role is the device's admin group (0.47): in it, out of isolated, or out of it.
			groups := slices.DeleteFunc(slices.Clone(p.Machine.Groups), func(g string) bool {
				return g == control.DeviceAdminGroup || admin && g == control.IsolatedGroup
			})
			if admin {
				groups = append(groups, control.DeviceAdminGroup)
			}
			u := store.PeerUpdate{Admin: &admin, Groups: &groups}
			if admin {
				u.Approved = &admin
			}
			return st.UpdatePeer(ctx, p.ID, u)
		}
	}
	return store.Peer{}, fmt.Errorf("no device named %s (ento admin peers lists them)", name)
}

// setGroups sets the device's own groups (device groups: the prefix is added), straight in the
// database: recovery, or a network nobody administers yet. Out of isolated means approved.
func setGroups(ctx context.Context, st store.Store, name string, groups []string) (store.Peer, error) {
	gs := make([]string, 0, len(groups))
	for _, g := range groups {
		if !strings.HasPrefix(g, control.DevicePrefix) {
			g = control.DevicePrefix + g
		}
		gs = append(gs, g)
	}
	approved := !slices.Contains(gs, control.IsolatedGroup)
	// The device's role is its groups (0.47; the built-in role groups here).
	admin := slices.Contains(gs, control.DeviceAdminGroup)
	operator := !admin && slices.Contains(gs, control.DeviceOperatorGroup)
	peers, err := st.Peers(ctx)
	if err != nil {
		return store.Peer{}, err
	}
	for _, p := range peers {
		if p.Hostname == name {
			return st.UpdatePeer(ctx, p.ID, store.PeerUpdate{Groups: &gs, Approved: &approved, Admin: &admin, Operator: &operator})
		}
	}
	return store.Peer{}, fmt.Errorf("no device named %s (ento admin peers lists them)", name)
}

// joinQR is how a words token is drawn as a QR code for phones: --qr and the domain (--domain).
type joinQR struct {
	draw   bool
	domain string
}

func tokenFlags(fs *flag.FlagSet) func() (control.TokenOptions, joinQR) {
	groups := fs.String("groups", "", "comma-separated groups for the enrolled peer")
	approve := fs.Bool("approve", false, "pre-approve the enrolled peer")
	admin := fs.Bool("admin", false, "make the enrolled peer an administrator")
	ttl := fs.Duration("ttl", time.Hour, "token lifetime")
	name := fs.String("name", "", "the enrolled device's name (default: z-<its host name>)")
	replace := fs.Bool("replace", false, "with --name: the new device takes over from a device that has the name")
	words := fs.Bool("words", false, "the token as words to read out (the device joins with ento agent install --join DOMAIN); --ttl at most 24h")
	qr := fs.Bool("qr", false, "with --words: also draw them as a QR code on the terminal, with the domain and the network's fingerprint, for the phone app to scan")
	domain := fs.String("domain", "", "with --qr: the domain whose _ento TXT record names this network (ento admin token: default the control nodes' --record-domain)")
	return func() (control.TokenOptions, joinQR) {
		return control.TokenOptions{Groups: splitList(*groups), Approve: *approve, Admin: *admin, TTL: *ttl,
			Name: *name, Replace: *replace, Words: *words}, joinQR{draw: *qr, domain: *domain}
	}
}

// check refuses a QR code that cannot be drawn, before a token is made.
func (q joinQR) check(words bool, needDomain bool) error {
	switch {
	case !q.draw && q.domain != "":
		return errors.New("--domain goes with --qr")
	case !q.draw:
		return nil
	case !words:
		return errors.New("--qr draws words (--words): tokens are for machines that automation enrolls, not for phones")
	case needDomain && q.domain == "":
		return errors.New("--qr needs --domain: the domain whose _ento TXT record names this network")
	}
	if fi, err := os.Stdout.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return errors.New("--qr draws on a terminal only")
	}
	if q.domain != "" {
		if _, err := token.JoinDomain(q.domain); err != nil {
			return fmt.Errorf("--domain: %v", err)
		}
	}
	return nil
}

// emitWords prints a words token: the words on stdout (with --qr after their QR code, the join code
// of domain), how to use them on stderr.
func emitWords(words, fingerprint string, expires time.Time, out string, q joinQR) error {
	if out != "" {
		return errors.New("--words are read out: not with --out")
	}
	if q.draw {
		j, err := token.NewJoinCode(q.domain, fingerprint, words)
		if err == nil {
			err = printQR(os.Stdout, j.String())
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "no QR code: %v; the words below work\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "scan it in the phone app (Scan the QR code): it joins the network of %s with the words below\n", j.Domain)
		}
	}
	fmt.Println(words)
	fmt.Fprintf(os.Stderr, "read these words out, with the domain whose _ento TXT record names this network (ento admin record);\n"+
		"on the device: sudo ento agent install --join DOMAIN (Windows: an administrator's PowerShell, without sudo).\n"+
		"It shows the network's fingerprint before asking for the words: %s\n"+
		"single use, expires %s\n", fingerprint, expires.UTC().Format(time.RFC3339))
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func emitToken(tok string, expires time.Time, out string) error {
	if out != "" {
		if err := os.WriteFile(out, []byte(tok+"\n"), 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "token written to %s (expires %s)\n", out, expires.UTC().Format(time.RFC3339))
		return nil
	}
	fmt.Println(tok)
	fmt.Fprintf(os.Stderr, "expires %s\n", expires.UTC().Format(time.RFC3339))
	return nil
}

// --- agent --------------------------------------------------------------------------------------

func agentFlags(fs *flag.FlagSet) *agent.Config {
	cfg := &agent.Config{Version: version}
	fs.StringVar(&cfg.StateDir, "state-dir", agent.DefaultStateDir, "directory holding the agent state")
	fs.StringVar(&cfg.Interface, "interface", "ento0", "WireGuard interface name")
	fs.IntVar(&cfg.ListenPort, "listen-port", agent.DefaultListenPort, "WireGuard UDP port (inside WSL 51830 means 51880, apart from Windows' own ento)")
	fs.IntVar(&cfg.MTU, "mtu", 1380, "interface MTU")
	fs.BoolVar(&cfg.Userspace, "userspace", false, "run WireGuard inside the agent even where the kernel has it (Linux); always so on other systems")
	fs.DurationVar(&cfg.LinkIdle, "link-idle", 7*24*time.Hour, "leave a linked network nothing was sent to for this long (0: never); ento agent link joins it again")
	fs.StringVar(&cfg.HardwareKey, "hardware-key", agent.HardwareKeyAuto, "auto: bind a key held by the TPM, where there is one (Linux), which signs check-ins and certifies a WireGuard key changed daily, so a copy of the state works nowhere else; off: never")
	fs.StringVar(&cfg.TPMDevice, "tpm-device", "/dev/tpmrm0", "the TPM (a socket: a software TPM, for tests)")
	fs.BoolVar(&cfg.NoSelfUpdate, "no-self-update", false, "leave the releases the network offers alone (0.37; Linux and macOS take them by themselves otherwise)")
	fs.BoolVar(&cfg.LogDrops, "log-drops", false, "log the new connections the inbound filter refuses, at most 20 a minute (kernel log, prefix \"ento-filter drop: \"; with WireGuard in the agent, the agent's log); install keeps it in the service")
	return cfg
}

// agentUp enrolls the device if needed and runs the agent until ctx ends.
func agentUp(ctx context.Context, cfg *agent.Config, tokenFile string, tokenStdin, deleteToken bool, join joinFlags) error {
	// Before enrolling or running: another WireGuard client holding the port must not stop it.
	agent.ChooseListenPort(cfg)
	if _, err := agent.LoadState(cfg.StateDir); errors.Is(err, agent.ErrNotEnrolled) {
		var tok string
		var err error
		if join.set() {
			tok, err = joinToken(ctx, join)
		} else {
			tok, err = readToken(tokenFile, tokenStdin)
		}
		if err != nil {
			return err
		}
		if tok == "" {
			return errors.New("not enrolled: provide a token with --token-file, --token-stdin or ENTO_TOKEN")
		}
		_, err = agent.Enroll(ctx, *cfg, tok)
		agent.SetEnrollError(cfg.StateDir, err) // what `ento agent install` waits on
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if deleteToken && tokenFile != "" {
		if err := os.Remove(tokenFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	// A release installed by a self-update that keeps failing to start is put back (0.37).
	agent.CheckPendingUpdate(cfg.StateDir, cfg.Version, log.Printf)
	return agent.Run(ctx, *cfg)
}

// waitEnrolled waits for the agent service to redeem the invitation `ento agent install` stored
// for it, printing a dot every half second, and says when the device is in the network or why not.
func waitEnrolled(ctx context.Context, stateDir, name string) error {
	fmt.Printf("joining network %s...", name)
	for i := 0; i < 180 && ctx.Err() == nil; i++ {
		if st, err := agent.LoadState(stateDir); err == nil {
			fmt.Printf("\njoined network %s as %s: complete\n", name, st.Address)
			return nil
		}
		if e := agent.EnrollError(stateDir); e != "" {
			fmt.Println()
			if strings.HasPrefix(e, "enrollment refused") {
				return fmt.Errorf("joining network %s failed: %s\nthe invitation is used up or withdrawn: ask an administrator for new words and install again", name, e)
			}
			return fmt.Errorf("joining network %s failed: %s\nthe agent tries again by itself: %s shows how it goes", name, e, statusCommand())
		}
		fmt.Print(".")
		time.Sleep(500 * time.Millisecond)
	}
	fmt.Println()
	return fmt.Errorf("not in network %s yet: the agent keeps trying (%s shows how it goes)", name, statusCommand())
}

// statusCommand is how a person shows the agent's status on this system, as administrator.
func statusCommand() string {
	if runtime.GOOS == "windows" {
		return "ento status, in a PowerShell run as administrator,"
	}
	return "sudo ento status"
}

// joinFlags are the flags of enrollment by words.
type joinFlags struct{ domain, record *string }

func addJoinFlags(fs *flag.FlagSet) joinFlags {
	return joinFlags{
		domain: fs.String("join", "", "enroll with words an administrator reads out: the domain whose _ento TXT record names the network (the words are asked for)"),
		record: fs.String("record", "", "with --join, or instead of it: the network record's text itself, not looked up in DNS"),
	}
}

func (j joinFlags) set() bool { return *j.domain != "" || *j.record != "" }

// joinToken builds the token that words stand for: it reads the network record (DNS, or --record),
// shows the network's fingerprint, asks for the words and stretches them (see token.WordsSecret).
func joinToken(ctx context.Context, j joinFlags) (string, error) {
	tok, _, err := joinTokenChecked(ctx, j, nil)
	return tok, err
}

// joinTokenChecked is joinToken that also returns the network record, and with check refuses the
// network before the words are asked for.
func joinTokenChecked(ctx context.Context, j joinFlags, check func(token.Record) error) (string, token.Record, error) {
	text, name := *j.record, *j.domain
	if text == "" {
		var err error
		if text, err = agent.LookupRecord(ctx, name, nil); err != nil {
			return "", token.Record{}, err
		}
	} else if name == "" {
		name = "(from --record)"
	}
	rec, err := token.ParseRecord(text)
	if err != nil {
		return "", token.Record{}, err
	}
	if check != nil {
		if err := check(rec); err != nil {
			return "", token.Record{}, err
		}
	}
	eps := make([]string, 0, len(rec.Controls))
	for _, c := range rec.Controls {
		eps = append(eps, c.Endpoint)
	}
	fmt.Fprintf(os.Stderr, "network %s: %s, control nodes %s\nfingerprint %s (your administrator can confirm it)\n",
		name, rec.Network, strings.Join(eps, " "), rec.Fingerprint())
	w, err := readWords()
	if err != nil {
		return "", token.Record{}, err
	}
	fmt.Fprintln(os.Stderr, "deriving the enrollment key from the words (a second or two)...")
	tok, err := rec.Token(w)
	if err != nil {
		return "", token.Record{}, err
	}
	enc, err := tok.Encode()
	return enc, rec, err
}

// readWords reads the words from the terminal, asking again when one is misspelled, or as one line
// of stdin when it is not a terminal. Never from the command line.
func readWords() ([]string, error) {
	in := bufio.NewReader(os.Stdin)
	fi, _ := os.Stdin.Stat()
	terminal := fi != nil && fi.Mode()&os.ModeCharDevice != 0
	for try := 0; ; try++ {
		if terminal {
			fmt.Fprintf(os.Stderr, "the %d words: ", token.WordCount)
		}
		line, err := in.ReadString('\n')
		if err != nil && (line == "" || !errors.Is(err, io.EOF)) {
			return nil, errors.New("no words read")
		}
		w, err := token.ParseWords(line)
		if err == nil {
			return w, nil
		}
		if !terminal || try == 2 {
			return nil, err
		}
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
}

// tokenRefused keeps tokens off Windows, where devices are people's and join with words; the
// service itself still reads the token install derived from the words for its first start.
func tokenRefused(file string, stdin bool) error {
	if runtime.GOOS != "windows" || agent.RunningAsService() {
		return nil
	}
	if file != "" || stdin || os.Getenv("ENTO_TOKEN") != "" {
		return errors.New("on Windows a device joins with the words an administrator reads out: ento agent install --join DOMAIN")
	}
	return nil
}

func readToken(file string, stdin bool) (string, error) {
	switch {
	case file != "":
		b, err := os.ReadFile(file)
		return strings.TrimSpace(string(b)), err
	case stdin:
		b, err := io.ReadAll(os.Stdin)
		return strings.TrimSpace(string(b)), err
	default:
		return strings.TrimSpace(os.Getenv("ENTO_TOKEN")), nil
	}
}

func agentCmd(ctx context.Context, args []string) error {
	cmd, args := sub(args)
	switch cmd {
	case "run", "up":
		fs := flag.NewFlagSet("agent "+cmd, flag.ExitOnError)
		cfg := agentFlags(fs)
		tokenFile := fs.String("token-file", "", "read the enrollment token from this file")
		tokenStdin := fs.Bool("token-stdin", false, "read the enrollment token from stdin")
		deleteToken := fs.Bool("delete-token", false, "delete --token-file once enrolled")
		join := addJoinFlags(fs)
		_ = fs.Parse(args)
		if join.set() && (*tokenFile != "" || *tokenStdin) {
			return errors.New("--join is instead of a token")
		}
		if err := tokenRefused(*tokenFile, *tokenStdin); err != nil {
			return err
		}
		run := func(ctx context.Context) error {
			return agentUp(ctx, cfg, *tokenFile, *tokenStdin, *deleteToken, join)
		}
		if handled, err := runService(run, cfg.StateDir); handled || err != nil {
			return err
		}
		// `up` on its own turns the installed service on. With a token, or as a service's own
		// command (older units run `agent up`), it runs the agent here, like `run`.
		if cmd == "up" && *tokenFile == "" && !*tokenStdin && !*deleteToken && os.Getenv("ENTO_TOKEN") == "" && !join.set() &&
			!agent.RunningAsService() && agent.ServiceInstalled(cfg.StateDir) {
			return serviceUp(ctx, cfg)
		}
		return run(ctx)

	case "down":
		fs := flag.NewFlagSet("agent down", flag.ExitOnError)
		cfg := agentFlags(fs)
		_ = fs.Parse(args)
		if err := agent.Down(*cfg); err != nil {
			return err
		}
		fmt.Println("the tunnel is down, and stays down across restarts, until `ento up`")
		return nil

	case "install":
		fs := flag.NewFlagSet("agent install", flag.ExitOnError)
		cfg := agentFlags(fs)
		tokenFile := fs.String("token-file", "", "enrollment token for the first start")
		tokenStdin := fs.Bool("token-stdin", false, "read the enrollment token from stdin")
		force := fs.Bool("force", false, "enrolled already: forget that enrollment (as uninstall --purge) and enroll with the token")
		join := addJoinFlags(fs)
		_ = fs.Parse(args)
		fs.Visit(func(f *flag.Flag) { // --log-drops=false: off, even if the service had it
			if f.Name == "log-drops" && !cfg.LogDrops {
				cfg.LogDropsOff = true
			}
		})
		// Before the words or the token: without a service manager they would be asked for nothing.
		if err := agent.ServiceSupported(); err != nil {
			return err
		}
		var tok string
		var err error
		if join.set() {
			if *tokenFile != "" || *tokenStdin {
				return errors.New("--join is instead of a token")
			}
			// Ask for the words only when they can be used.
			if st, err := agent.LoadState(cfg.StateDir); err == nil && !*force {
				return fmt.Errorf("this device is already enrolled (address %s); --force replaces that enrollment with the words' "+
					"(the old device stays on the control plane until an administrator deletes it)", st.Address)
			}
			tok, err = joinToken(ctx, join)
		} else {
			if err := tokenRefused(*tokenFile, *tokenStdin); err != nil {
				return err
			}
			tok, err = readToken(*tokenFile, *tokenStdin)
		}
		if err != nil {
			return err
		}
		if err := agent.Install(*cfg, tok, *force); err != nil {
			return err
		}
		if agent.IsDown(cfg.StateDir) {
			fmt.Println("the ento agent is installed; it stays down (`ento down`) until `ento up`")
			return nil
		}
		fmt.Println("the ento agent is installed and started")
		if tok == "" {
			return nil
		}
		// The service redeems the invitation: wait until it has, or says why not.
		name := *join.domain
		if name == "" {
			name = "of the invitation"
		}
		return waitEnrolled(ctx, cfg.StateDir, name)

	case "uninstall":
		fs := flag.NewFlagSet("agent uninstall", flag.ExitOnError)
		cfg := agentFlags(fs)
		purge := fs.Bool("purge", false, "also delete the state (the device must enroll again)")
		_ = fs.Parse(args)
		return agent.Uninstall(*cfg, *purge)

	case "login":
		fs := flag.NewFlagSet("agent login", flag.ExitOnError)
		cfg := agentFlags(fs)
		network := networkFlag(fs)
		noQR := fs.Bool("no-qr", false, "do not draw the sign-in link as a QR code")
		_ = fs.Parse(args)
		baseDir := cfg.StateDir
		if err := useNetwork(cfg, *network); err != nil {
			return err
		}
		if severalNetworks(baseDir) {
			fmt.Printf("Signing in to %s (this device is in several networks: --network chooses)\n\n", networkName(&agent.Config{StateDir: baseDir}, *network))
		}
		var showQR func(string)
		if !*noQR && isTerminal(os.Stdout) {
			showQR = func(link string) {
				fmt.Fprint(os.Stdout, "\n\nOr scan this with a phone and sign in there (no security key needed on this device):\n\n")
				_ = printQR(os.Stdout, link)
			}
		}
		if personChannel(cfg.StateDir) {
			return agent.LoginViaAgent(ctx, os.Stdout, showQR)
		}
		return agent.Login(ctx, *cfg, os.Stdout, showQR)

	case "join":
		return joinCmd(ctx, args)

	case "leave":
		return leaveCmd(ctx, args)

	case "link", "unlink":
		fs := flag.NewFlagSet("agent "+cmd, flag.ExitOnError)
		cfg := agentFlags(fs)
		proxy := fs.String("proxy", "", "link: also serve an HTTP proxy into the linked network on this loopback address:port (\"off\" stops it)")
		proxyPorts := fs.String("proxy-ports", "", "link: the only ports the proxy opens connections to, e.g. 443,9199 (default: all)")
		_ = fs.Parse(args)
		if cmd == "link" && fs.NArg() == 1 && *proxy != "" {
			addr := *proxy
			if addr == "off" {
				addr = ""
			}
			if err := agent.SetLinkProxy(cfg.StateDir, fs.Arg(0), addr, *proxyPorts); err != nil {
				return err
			}
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("usage: ento agent %s NAME", cmd)
		}
		return linkCmd(ctx, cfg.StateDir, cmd, fs.Arg(0))

	case "netns": // used by the ento-netns@ systemd unit
		if len(args) != 2 || !agent.ValidLinkName(args[1]) {
			return errors.New("usage: ento agent netns add|del NAME")
		}
		if args[0] == "add" {
			return agent.CreateNamespace(args[1])
		}
		return agent.DeleteNamespace(args[1])

	case "approve":
		fs := flag.NewFlagSet("agent approve", flag.ContinueOnError)
		cfg := agentFlags(fs)
		network := networkFlag(fs)
		user := fs.String("user", os.Getenv("PAM_USER"), "the account to sign in to (default $PAM_USER)")
		service := fs.String("service", os.Getenv("PAM_SERVICE"), "what is signed in to (default $PAM_SERVICE)")
		timeout := fs.Duration("timeout", 60*time.Second, "how long to wait for the answer (10s to 2m)")
		if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *user == "" || *service == "" {
			return exitCode{64, "usage: ento agent approve [--user NAME] [--service NAME] [--timeout 60s] (or as a pam_exec step)"}
		}
		if t := os.Getenv("PAM_TYPE"); t != "" && t != "auth" {
			return exitCode{64, "a sign-in approval belongs in the auth stack, not " + t}
		}
		baseDir := cfg.StateDir
		if err := useNetwork(cfg, *network); err != nil {
			return exitCode{64, err.Error()}
		}
		label := ""
		if severalNetworks(baseDir) {
			label = " (" + networkName(&agent.Config{StateDir: baseDir}, *network) + ")"
		}
		return agentApprove(ctx, cfg, *user, *service, *timeout, label)

	case "approvals":
		return approvalsCmd(ctx, args)

	case "exit":
		fs := flag.NewFlagSet("agent exit", flag.ExitOnError)
		cfg := agentFlags(fs)
		_ = fs.Parse(args)
		if fs.NArg() > 1 {
			return errors.New("usage: ento exit [NAME|off|default]")
		}
		if fs.NArg() == 0 {
			return showExits(cfg.StateDir)
		}
		if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
			return errors.New("this system cannot use exits yet (Linux and Android can)")
		}
		choice := fs.Arg(0)
		if choice == "default" {
			choice = ""
		}
		if err := agent.SetExitChoice(cfg.StateDir, choice); err != nil {
			if errors.Is(err, os.ErrPermission) {
				return errors.New("run as root: the choice is kept in the agent's state")
			}
			return err
		}
		return awaitExit(cfg.StateDir, choice)

	case "whoami":
		fs := flag.NewFlagSet("agent whoami", flag.ExitOnError)
		cfg := agentFlags(fs)
		network := networkFlag(fs)
		asJSON := fs.Bool("json", false, "print user, user_name and session_active as JSON")
		_ = fs.Parse(args)
		if err := useNetwork(cfg, *network); err != nil {
			return exitCode{1, err.Error()}
		}
		r, running := agent.RunningAgent(cfg.StateDir)
		var active bool
		if !running && personChannel(cfg.StateDir) {
			st, err := agent.SessionStatus(ctx)
			if err != nil {
				return exitCode{1, err.Error()}
			}
			r.User, r.UserName, active = st.User, st.UserName, st.SessionActive
		} else if !running {
			return exitCode{1, "the agent is not running (run as root: its state is root's)"}
		} else {
			// Agents before 0.27 announce no person layer: their session is open unless it ended.
			active = r.User != "" && !r.LoginRequired && (r.PersonActive || r.PersonSince == "" && !personAware(r.Version))
		}
		if *asJSON {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"user": r.User, "user_name": r.UserName, "session_active": active})
		} else if r.User != "" {
			fmt.Println(r.User)
		}
		switch {
		case r.User == "":
			return exitCode{1, ""}
		case !active:
			return exitCode{2, ""}
		}
		return nil

	case "logout":
		fs := flag.NewFlagSet("agent logout", flag.ExitOnError)
		cfg := agentFlags(fs)
		network := networkFlag(fs)
		timeout := fs.Duration("timeout", 5*time.Second, "how long to try telling the control plane before leaving it to the agent")
		_ = fs.Parse(args)
		if err := useNetwork(cfg, *network); err != nil {
			return err
		}
		var delivered bool
		var err error
		if personChannel(cfg.StateDir) {
			delivered, err = agent.LogoutViaAgent(ctx)
		} else {
			delivered, err = agent.Logout(ctx, *cfg, *timeout)
		}
		switch {
		case err != nil:
			return err
		case delivered:
			fmt.Println("signed out: the person's rights on this device ended (the machine's stay)")
		default:
			fmt.Println("the control plane could not be reached: the agent signs out when it can")
		}
		return nil

	case "posture":
		fs := flag.NewFlagSet("agent posture", flag.ExitOnError)
		asJSON := fs.Bool("json", false, "print the report as the control nodes receive it")
		_ = fs.Parse(args)
		p := agent.CollectPosture(ctx, version)
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(p)
		}
		fmt.Println(agent.PostureSummary(p))
		for _, n := range agent.PostureNotes() {
			fmt.Fprintln(os.Stderr, "note: "+n)
		}
		if os.Geteuid() > 0 {
			fmt.Fprintln(os.Stderr, "(not root: some facts may be unknown here that the agent, running as root, reports)")
		}
		return nil

	case "status":
		fs := flag.NewFlagSet("agent status", flag.ExitOnError)
		cfg := agentFlags(fs)
		network := networkFlag(fs)
		_ = fs.Parse(args)
		baseDir := cfg.StateDir
		if err := useNetwork(cfg, *network); err != nil {
			return err
		}
		several := severalNetworks(baseDir)
		if several {
			fmt.Printf("network:    %s\n", networkName(&agent.Config{StateDir: baseDir}, *network))
		}
		st, err := agent.LoadState(cfg.StateDir)
		switch {
		case err != nil && personChannel(cfg.StateDir):
			return personStatus(ctx)
		case errors.Is(err, os.ErrPermission):
			return errors.New("the agent's state is root's: " + statusCommand())
		case errors.Is(err, agent.ErrNotEnrolled) && agent.Joining(cfg.StateDir):
			if e := agent.EnrollError(cfg.StateDir); e != "" {
				return fmt.Errorf("joining: not in the network yet, the last attempt failed: %s", e)
			}
			fmt.Println("joining: the agent is redeeming its invitation (a few seconds)")
			return nil
		case err != nil:
			return err
		}
		fmt.Printf("address:    %s (%s)\npublic key: %s\n", st.Address, st.Network, wgtypes.Key(st.PrivateKey).PublicKey())
		for _, w := range agent.OverlayWarnings(st.Network) {
			fmt.Printf("WARNING:    %s\n", w)
		}
		r, running := agent.RunningAgent(cfg.StateDir)
		switch {
		case !running && agent.IsDown(cfg.StateDir):
			fmt.Println("agent:      down - `ento up` turns the tunnel on again")
			return nil
		case !running:
			fmt.Println("agent:      not running")
		case r.LoginRequired:
			fmt.Println("session:    ENDED - run `" + loginCommand + "` to reconnect")
		}
		if running && r.FilterFailed != "" {
			fmt.Printf("WARNING:    the inbound filter could not be applied (%s): only the control nodes are peers until it can\n", r.FilterFailed)
		}
		if running && len(r.Routes) > 0 {
			fmt.Printf("routes:     %s (through gateways)\n", strings.Join(r.Routes, ", "))
		}
		if running && len(r.Serves) > 0 {
			fmt.Printf("gateway of: %s\n", strings.Join(r.Serves, ", "))
		}
		if running && r.DNSDomain != "" {
			fmt.Printf("dns:        %s, answered by %s\n", r.DNSDomain, r.Resolver)
		}
		if running && r.HardwareKey != "" {
			line := "hw key:     " + r.HardwareKey
			if r.KeyCreatedAt != "" && strings.HasSuffix(r.HardwareKey, ", bound") {
				line += "; WireGuard key from " + r.KeyCreatedAt + ", changed daily"
			}
			fmt.Println(line)
		}
		if running && r.ExitFor {
			fmt.Println("exit for:   other devices (their internet traffic leaves through this one)")
		}
		if running {
			for _, e := range r.Exits {
				fmt.Printf("exit:       %s\n", exitLine(e))
			}
		}
		if running && (r.User != "" || r.UserName != "") {
			who := r.User
			if r.UserName != "" && r.UserName != r.User {
				who = strings.TrimSpace(who + " (" + r.UserName + ")")
			}
			fmt.Printf("user:       %s\n", who)
			switch {
			case r.PersonActive:
				fmt.Printf("session:    open since %s: the person's rights are this device's too (ento logout ends them)\n", localTime(r.PersonSince))
			case personAware(r.Version) && !r.LoginRequired:
				fmt.Println("session:    closed: the device has its machine's rights; signing in to it again (approved on the person's phone) reopens it")
			}
		}
		if running {
			printPosture(r)
		}
		status, err := agent.Peers(*cfg)
		if err != nil && !running {
			return nil // no interface without the agent (a kernel one would still answer)
		} else if err != nil {
			return err
		}
		names := map[wgtypes.Key]string{}
		for _, c := range st.Controls {
			if k, err := wgtypes.ParseKey(c.PublicKey); err == nil {
				names[k] = "control " + c.Name
			}
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "\nPEER\tROLE\tENDPOINT\tLAST HANDSHAKE\tRX\tTX")
		for k, s := range status {
			role := names[k]
			switch {
			case role != "":
			case strings.HasPrefix(s.Endpoint, "127.0.0.1:"):
				role = "peer (relayed)"
			default:
				role = "peer (direct)"
			}
			hs := "never"
			if !s.LastHandshake.IsZero() {
				hs = time.Since(s.LastHandshake).Round(time.Second).String() + " ago"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\n", k, role, s.Endpoint, hs, s.RxBytes, s.TxBytes)
		}
		if err := w.Flush(); err != nil {
			return err
		}
		if several {
			if err := networksStatus(baseDir, networkName(&agent.Config{StateDir: baseDir}, *network)); err != nil {
				return err
			}
		}
		return linkStatus(baseDir)
	}
	return errors.New("usage: ento agent install|uninstall|up|down|run|login|status|link|unlink [flags]")
}

// printPosture shows the device's latest posture report and the checks it fails.
func printPosture(r agent.Running) {
	if r.Posture == nil {
		fmt.Println("posture:    not reported yet")
	} else {
		when := r.PostureReportedAt
		if t, err := time.Parse(time.RFC3339, when); err == nil {
			when = api.HumanDuration(time.Since(t)) + " ago"
		}
		fmt.Printf("posture:    %s (reported %s)\n", cell(agent.PostureSummary(*r.Posture)), when)
	}
	for _, f := range agent.FailingText(r.PostureFailing) {
		fmt.Printf("            FAILS %s: the policies requiring it leave this device out\n", cell(f))
	}
}

// serviceUp turns the installed agent service on (again) and waits until the agent runs.
func serviceUp(ctx context.Context, cfg *agent.Config) error {
	if err := agent.Up(*cfg); err != nil {
		return err
	}
	for i := 0; i < 60 && ctx.Err() == nil; i++ {
		if _, ok := agent.RunningAgent(cfg.StateDir); ok {
			fmt.Println("the tunnel is up; check with: ento status")
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("the service is started, but the agent has not come up yet: see `ento status` and the service's log")
}

// linkCmd asks the running agent to join or leave a linked network and waits for the outcome.
func linkCmd(ctx context.Context, stateDir, cmd, name string) error {
	if cmd == "unlink" {
		if err := agent.RequestUnlink(stateDir, name); err != nil {
			return err
		}
		for i := 0; i < 60 && ctx.Err() == nil; i++ {
			if !slices.Contains(agent.Links(stateDir), name) {
				fmt.Printf("left %s\n", name)
				return nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return errors.New("the agent did not act on the request (is ento-agent running?)")
	}
	if _, err := agent.LoadLinkState(stateDir, name); err == nil {
		fmt.Printf("already linked to %s (namespace %s)\n", name, agent.NamespaceName(name))
		return nil
	}
	if r, ok := agent.RunningAgent(stateDir); !ok || !r.Links {
		return errors.New("the ento agent service is not running a version that handles linked networks; " +
			"update it with `sudo ento agent install` (after installing the new binary) and try again")
	}
	if err := agent.RequestLink(stateDir, name); err != nil {
		return err
	}
	fmt.Printf("joining %s", name)
	for i := 0; i < 180 && ctx.Err() == nil; i++ {
		if ls, err := agent.LoadLinkState(stateDir, name); err == nil {
			fmt.Printf("\n\nlinked to %s as %s, approved until %s\n", name, ls.Address, ls.ApprovedUntil.Local().Format(time.RFC1123))
			fmt.Printf("run commands for it in its namespace, e.g.:\n    sudo ip netns exec %s ping <peer>\n", agent.NamespaceName(name))
			return nil
		}
		if e := agent.LinkError(stateDir, name); e != "" {
			fmt.Println()
			return fmt.Errorf("joining %s failed: %s (retrying in the background; `ento agent unlink %s` cancels)", name, e, name)
		}
		fmt.Print(".")
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New("\nthe agent did not act on the request (is ento-agent running?)")
}

func linkStatus(stateDir string) error {
	names := agent.Links(stateDir)
	if len(names) == 0 {
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "\nLINKED NETWORK\tNAMESPACE\tADDRESS\tAPPROVED UNTIL\tSTATE")
	for _, n := range names {
		ls, err := agent.LoadLinkState(stateDir, n)
		switch {
		case err == nil:
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\tjoined\n", n, agent.NamespaceName(n), ls.Address, ls.ApprovedUntil.Local().Format(time.RFC3339))
		case agent.LinkError(stateDir, n) != "":
			fmt.Fprintf(w, "%s\t%s\t-\t-\tfailed: %s\n", n, agent.NamespaceName(n), agent.LinkError(stateDir, n))
		default:
			fmt.Fprintf(w, "%s\t%s\t-\t-\tjoining\n", n, agent.NamespaceName(n))
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	for _, n := range names {
		for _, f := range agent.FailingText(agent.LinkHomePostureFailing(stateDir, n)) {
			fmt.Printf("link %s: FAILS %s, which this network's link requires: no credential for %s until it passes\n", n, cell(f), n)
		}
		for _, f := range agent.FailingText(agent.LinkPostureFailing(stateDir, n)) {
			fmt.Printf("link %s: FAILS %s: the policies requiring it leave this device out there\n", n, cell(f))
		}
	}
	return nil
}

// --- admin --------------------------------------------------------------------------------------

// cell makes a value from the network safe to print in a table: no control characters (a device's
// reported host name could otherwise rewrite the terminal), "-" for nothing.
func cell(s string) string {
	if s == "" {
		return "-"
	}
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
}

// takeFlag removes --name VALUE (or -name, or =VALUE) from anywhere in args and returns its value
// ("" if absent). A flag given twice, or without a value, is an error.
func takeFlag(args []string, name string) (string, []string, error) {
	value, found := "", false
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		v, ok := "", false
		for _, f := range []string{"--" + name, "-" + name} {
			if a == f {
				if i+1 >= len(args) {
					return "", nil, fmt.Errorf("%s needs a value", f)
				}
				v, ok = args[i+1], true
				i++
			} else if after, cut := strings.CutPrefix(a, f+"="); cut {
				v, ok = after, true
			}
		}
		if !ok {
			rest = append(rest, a)
			continue
		}
		if found {
			return "", nil, fmt.Errorf("--%s given twice", name)
		}
		if v == "" {
			return "", nil, fmt.Errorf("--%s needs a value", name)
		}
		value, found = v, true
	}
	return value, rest, nil
}

func adminCmd(ctx context.Context, args []string) error {
	stateDir := os.Getenv("ENTO_STATE_DIR")
	if stateDir == "" {
		stateDir = agent.DefaultStateDir
	}
	// --link NAME: administer a linked network, as this device's membership there (its key, its
	// namespace), where that network made it an administrator. --network DOMAIN: administer another
	// network the device joined (ento join), with its key there. Both are taken anywhere on the
	// line: before 0.56.6 only right after `admin`, and `ento admin peers --network D` silently
	// administered the first network.
	link, args, err := takeFlag(args, "link")
	if err != nil {
		return err
	}
	network, args, err := takeFlag(args, "network")
	if err != nil {
		return err
	}
	if link != "" && network != "" {
		return errors.New("--link or --network, not both")
	}
	if network != "" {
		dir, err := agent.NetworkStateDir(stateDir, network)
		if err != nil {
			return err
		}
		stateDir = dir
	}
	cmd, rest := sub(args)
	var c *agent.AdminClient
	if link == "" {
		st, err := agent.LoadState(stateDir)
		if err != nil {
			return fmt.Errorf("admin commands run as root (administrator) on an enrolled admin peer: %w", err)
		}
		c = &agent.AdminClient{Controls: st.Controls, Key: wgtypes.Key(st.PrivateKey)}
	} else {
		ls, err := agent.LoadLinkState(stateDir, link)
		if err != nil {
			return fmt.Errorf("linked network %s: %w", link, err)
		}
		hc, closeNS, err := agent.LinkHTTPClient(link)
		if err != nil {
			return err
		}
		defer closeNS()
		c = &agent.AdminClient{Controls: ls.Controls, Key: wgtypes.Key(ls.PrivateKey), HTTP: hc}
	}

	switch cmd {
	case "ui":
		// The page shows a code; approving it here, with the device's key, opens the page's
		// session. Nothing secret goes to the browser on a command line other programs can read.
		fs := flag.NewFlagSet("admin ui", flag.ExitOnError)
		noBrowser := fs.Bool("no-browser", false, "do not open a browser (open the page yourself)")
		_ = fs.Parse(rest)
		code := fs.Arg(0)
		if code == "" {
			var ui api.AdminUI
			if err := c.Do(ctx, "GET", api.PathAdminUI, nil, &ui); err != nil {
				return err
			}
			shown := agent.Printable(ui.URL)
			switch {
			case link != "":
				fmt.Fprintf(os.Stderr, "Open %s in a browser running inside %s.\n", shown, agent.NamespaceName(link))
			case !*noBrowser && agent.OpenBrowser(ui.URL):
				fmt.Fprintf(os.Stderr, "%s is opening in your browser.\n", shown)
			default:
				fmt.Fprintf(os.Stderr, "Open %s in a browser on this device.\n", shown)
			}
			fmt.Fprint(os.Stderr, "Then type the code the page shows: ")
			line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if code = strings.TrimSpace(line); code == "" {
				return errors.New("no code: run `ento admin ui CODE` with the code the page shows")
			}
		}
		var ok api.ApprovedAdminUI
		if err := c.Do(ctx, "POST", api.PathAdminUI, api.ApproveAdminUIRequest{Code: code}, &ok); err != nil {
			return err
		}
		opened := ok.OpenedAt
		if t, err := time.Parse(time.RFC3339, ok.OpenedAt); err == nil {
			opened = t.Local().Format("15:04:05")
		}
		fmt.Fprintf(os.Stderr, "Approved the page opened at %s in %s.\n", opened, cell(ok.Browser))
		fmt.Fprintln(os.Stderr, "It opens in a moment, for this device only, for up to 8 hours (30 minutes unused).")
		fmt.Fprintln(os.Stderr, "If you did not open that page, sign it out now: open the page and press Sign out, or remove this device's admin role.")
		return nil

	case "token":
		tfs := flag.NewFlagSet("admin token", flag.ExitOnError)
		opts := tokenFlags(tfs)
		out := tfs.String("out", "", "write the token to this file (mode 0600) instead of stdout")
		_ = tfs.Parse(rest)
		o, q := opts()
		if o.Words && *out != "" {
			return errors.New("--words are read out: not with --out")
		}
		if err := q.check(o.Words, false); err != nil {
			return err
		}
		var res api.CreateTokenResponse
		if err := c.Do(ctx, "POST", api.PathTokens, api.CreateTokenRequest{Groups: o.Groups, Approve: o.Approve,
			Admin: o.Admin, TTLSeconds: int(o.TTL.Seconds()), Name: o.Name, Replace: o.Replace, Words: o.Words,
			QRDomain: q.domain}, &res); err != nil {
			return err
		}
		exp, _ := time.Parse(time.RFC3339, res.ExpiresAt)
		if o.Words {
			if res.Words == "" {
				return errors.New("the control plane does not make words (older than ento 0.20): no token was created as words")
			}
			if q.draw && q.domain == "" {
				// The control nodes' record domain, which their join code names.
				if j, err := token.ParseJoinCode(res.JoinCode); err == nil {
					q.domain = j.Domain
				} else {
					fmt.Println(res.Words)
					return errors.New("no QR code: the control nodes have no --record-domain; give --domain (the words above work: read them out)")
				}
			}
			return emitWords(res.Words, res.Fingerprint, exp, "", q)
		}
		return emitToken(res.Token, exp, *out)

	case "record":
		var res api.NetworkRecordResponse
		if err := c.Do(ctx, "GET", api.PathRecord, nil, &res); err != nil {
			if code := agent.HTTPStatus(err); code == 404 || code == 405 {
				return errors.New("the control plane has no network record (older than ento 0.20)")
			}
			return err
		}
		fmt.Println(res.Record)
		fmt.Fprintf(os.Stderr, "publish as the TXT record %s.<domain>; fingerprint %s\n", token.RecordName, res.Fingerprint)
		return nil

	case "peers":
		var peers []api.PeerInfo
		if err := c.Do(ctx, "GET", api.PathPeers, nil, &peers); err != nil {
			return err
		}
		if len(rest) > 0 && rest[0] == "--json" {
			return json.NewEncoder(os.Stdout).Encode(peers)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNAME\tADDRESS\tUSER\tAPPROVED\tROLE\tGROUPS\tENDPOINT\tLAST SEEN\tREPORTED HOST NAME\tHW KEY\tPOSTURE\tFAILS")
		for _, p := range peers {
			approved := fmt.Sprint(p.Approved)
			if p.Suspended {
				approved = "suspended"
				if p.CloneSuspected != "" {
					approved = "suspended:copied?" // a check-in's suspicion (peers --json says why)
				}
			}
			role := "-"
			switch {
			case p.Admin:
				role = "admin"
			case p.Operator:
				role = "operator"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.ID, cell(p.Hostname), p.Address, cell(p.User),
				approved, role, cell(strings.Join(p.Groups, ",")), cell(p.Endpoint), cell(p.LastSeen), cell(p.ReportedHostname),
				cell(p.HardwareKey), cell(postureCell(p)), cell(failsCell(p)))
		}
		return w.Flush()

	case "tokens":
		var toks []api.TokenInfo
		if err := c.Do(ctx, "GET", api.PathTokens, nil, &toks); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tDEVICE NAME\tGROUPS\tAPPROVE\tADMIN\tEXPIRES\tCREATED BY")
		for _, t := range toks {
			by := t.CreatedBy
			if t.Authority != "" {
				by = "authority " + t.Authority
			}
			name := t.Name
			if t.Replace {
				name += " (replaces)"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%v\t%v\t%s\t%s\n", t.ID, cell(name), cell(strings.Join(t.Groups, ",")), t.Approve,
				t.Admin, t.ExpiresAt, cell(by))
		}
		return w.Flush()

	case "rename", "confirm-name":
		var req api.UpdatePeerRequest
		switch {
		case cmd == "rename" && len(rest) == 2:
			req.Hostname = &rest[1]
		case cmd == "confirm-name" && len(rest) == 1:
			req.UseReportedHostname = true
		default:
			return errors.New("usage: ento admin rename ID NAME | ento admin confirm-name ID")
		}
		id, err := oneID(rest[:1])
		if err != nil {
			return err
		}
		var p api.PeerInfo
		if err := c.Do(ctx, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, id), req, &p); err != nil {
			return err
		}
		fmt.Printf("device %d is now %s\n", p.ID, p.Hostname)
		return nil

	case "revoke":
		id, err := oneID(rest)
		if err != nil {
			return err
		}
		return c.Do(ctx, "DELETE", fmt.Sprintf("%s/%d", api.PathTokens, id), nil, nil)

	case "suspend", "resume":
		v := cmd == "suspend"
		if len(rest) > 0 && (rest[0] == "--user" || strings.HasPrefix(rest[0], "--user=")) {
			user, ok := strings.CutPrefix(rest[0], "--user=")
			if !ok {
				if len(rest) != 2 {
					return fmt.Errorf("usage: ento admin %s --user USER", cmd)
				}
				user = rest[1]
			} else if len(rest) != 1 {
				return fmt.Errorf("usage: ento admin %s --user USER", cmd)
			}
			var res api.SuspendUserResult
			if err := c.Do(ctx, "POST", api.PathUserSuspension, api.SuspendUserRequest{User: user, Suspended: v}, &res); err != nil {
				return err
			}
			for _, p := range res.Changed {
				fmt.Printf("%s: %d %s\n", map[bool]string{true: "suspended", false: "resumed"}[v], p.ID, p.Hostname)
			}
			for _, d := range res.Skipped {
				fmt.Printf("left as it was: %d %s (%s)\n", d.ID, d.Hostname, d.Reason)
			}
			if len(res.Changed) == 0 {
				return fmt.Errorf("no device of %s changed", user)
			}
			return nil
		}
		id, err := oneID(rest)
		if err != nil {
			return err
		}
		return c.Do(ctx, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, id), api.UpdatePeerRequest{Suspended: &v}, nil)

	case "approve", "unapprove":
		id, err := oneID(rest)
		if err != nil {
			return err
		}
		v := cmd == "approve"
		return c.Do(ctx, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, id), api.UpdatePeerRequest{Approved: &v}, nil)

	case "signout":
		id, err := oneID(rest)
		if err != nil {
			return err
		}
		return c.Do(ctx, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, id), api.UpdatePeerRequest{SignOut: true}, nil)

	case "unbind":
		id, err := oneID(rest)
		if err != nil {
			return err
		}
		if err := c.Do(ctx, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, id), api.UpdatePeerRequest{UnbindHardwareKey: true}, nil); err != nil {
			return err
		}
		fmt.Println("hardware key released: the device's next hardware key binds (resume it too if it was suspended)")
		return nil

	case "groups":
		if len(rest) != 2 {
			return errors.New("usage: ento admin groups ID GROUP[,GROUP...]")
		}
		id, err := oneID(rest[:1])
		if err != nil {
			return err
		}
		g := splitList(rest[1])
		return c.Do(ctx, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, id), api.UpdatePeerRequest{Groups: &g}, nil)

	case "role":
		if len(rest) != 2 || (rest[1] != "admin" && rest[1] != "operator" && rest[1] != "none") {
			return errors.New("usage: ento admin role ID admin|operator|none")
		}
		id, err := oneID(rest[:1])
		if err != nil {
			return err
		}
		admin, operator := rest[1] == "admin", rest[1] == "operator"
		return c.Do(ctx, "PATCH", fmt.Sprintf("%s/%d", api.PathPeers, id), api.UpdatePeerRequest{Admin: &admin, Operator: &operator}, nil)

	case "delete":
		id, err := oneID(rest)
		if err != nil {
			return err
		}
		return c.Do(ctx, "DELETE", fmt.Sprintf("%s/%d", api.PathPeers, id), nil, nil)

	case "policies":
		var pols []api.Policy
		if err := c.Do(ctx, "GET", api.PathPolicies, nil, &pols); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSOURCE\t\tDESTINATION\tPORTS\tSOURCE POSTURE")
		for _, p := range pols {
			arrow, open := "<-> (an old rule both ways: replace it with two)", "all"
			if p.OneWay {
				arrow = "->"
			}
			if len(p.Ports) > 0 {
				open = strings.Join(p.Ports, ",")
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", p.ID, cell(sourceWord(p)), arrow, cell(p.Destination), cell(open),
				cell(strings.Join(p.Posture, ",")))
		}
		return w.Flush()

	case "allow":
		checks, args, err := postureFlag(rest)
		var rules []string
		var on string
		if err == nil {
			rules, args, err = ruleFlags(args)
		}
		if err == nil {
			on, args, err = onFlag(args)
		}
		if err != nil || len(args) != 2 {
			if err != nil && strings.HasPrefix(err.Error(), "rules go one way") {
				return err
			}
			return errors.New("usage: ento admin allow WHO DESTINATION [--on DEVICE_GROUP] [--ports RULE[,RULE...]] [--posture CHECK[,CHECK...]] (WHO opens, DESTINATION answers)")
		}
		if len(checks) > 0 {
			// A control node older than 0.13 would create the policy and ignore its checks: ask
			// first whether it knows posture checks at all (and that they exist).
			if err := knowsChecks(ctx, c, checks, "policy"); err != nil {
				return err
			}
		}
		// WHO@DEVICES, as ento admin policies writes it, is WHO with --on DEVICES.
		if who, devs, ok := strings.Cut(args[0], "@"); ok && on == "" {
			args[0], on = who, devs
		}
		req := api.Policy{Source: args[0], On: on, Destination: args[1], Posture: checks, OneWay: true}
		if rules != nil && !slices.Equal(rules, []string{"all"}) {
			req.Ports = rules
		}
		var p api.Policy
		if err := c.Do(ctx, "POST", api.PathPolicies, req, &p); err != nil {
			return err
		}
		printWarnings(p.Warnings)
		if req.OneWay && !p.OneWay || len(req.Ports) > 0 && len(p.Ports) == 0 {
			// A control node older than 0.19 keeps neither: never leave that unsaid.
			return fmt.Errorf("the control plane made it both ways or on every port (older than ento 0.19?): policy %d allows %s <-> %s on every port; remove it with `ento admin disallow %d` if that is not what you want",
				p.ID, p.Source, p.Destination, p.ID)
		}
		if len(checks) > 0 && len(p.Posture) == 0 {
			// A control node older than 0.13 answered the probe: never leave that unsaid.
			return fmt.Errorf("the control plane ignored --posture (older than ento 0.13?): policy %d allows %s <-> %s WITHOUT checks; remove it with `ento admin disallow %d` if that is not what you want",
				p.ID, p.Source, p.Destination, p.ID)
		}
		if on != "" && p.On == "" && on != "*" {
			// A control node older than 0.53 knows no --on: never leave that unsaid.
			return fmt.Errorf("the control plane ignored --on (older than ento 0.53?): policy %d lets %s reach %s on ANY device; remove it with `ento admin disallow %d` if that is not what you want",
				p.ID, p.Source, p.Destination, p.ID)
		}
		p.Warnings = nil
		out, _ := json.Marshal(p)
		fmt.Println(string(out))
		return nil

	case "audit":
		return auditCmd(ctx, c, rest)

	case "policy":
		checks, args, err := postureFlag(rest)
		var rules []string
		oneWayOnly := slices.Contains(rest, "--one-way") // an old rule both ways made one way
		if err == nil {
			rules, args, err = ruleFlags(args)
		}
		if err != nil || len(args) != 1 || checks == nil && rules == nil && !oneWayOnly {
			if err != nil && strings.HasPrefix(err.Error(), "rules go one way") {
				return err
			}
			return errors.New("usage: ento admin policy ID --posture CHECK[,CHECK...]|none | --ports RULE[,RULE...]|all")
		}
		id, err := oneID(args)
		if err != nil {
			return err
		}
		var p api.Policy
		if checks != nil {
			if err := c.Do(ctx, "PATCH", fmt.Sprintf("%s/%d", api.PathPolicies, id), api.UpdatePolicyRequest{Posture: checks}, &p); err != nil {
				return err
			}
			printWarnings(p.Warnings)
		}
		if rules != nil || oneWayOnly {
			// What is not given stays as it is.
			var pols []api.Policy
			if err := c.Do(ctx, "GET", api.PathPolicies, nil, &pols); err != nil {
				return err
			}
			i := slices.IndexFunc(pols, func(x api.Policy) bool { return x.ID == id })
			if i < 0 {
				return fmt.Errorf("no policy %d", id)
			}
			req := api.PolicyRulesRequest{OneWay: true, Ports: pols[i].Ports}
			if rules != nil {
				req.Ports = rules
				if slices.Equal(rules, []string{"all"}) {
					req.Ports = nil
				}
			}
			if err := c.Do(ctx, "PUT", fmt.Sprintf("%s/%d/rules", api.PathPolicies, id), req, &p); err != nil {
				if code := agent.HTTPStatus(err); code == 404 || code == 405 {
					return errors.New("the control plane does not know a policy's direction and ports (older than ento 0.19): upgrade its control nodes first; nothing changed")
				}
				return err
			}
			printWarnings(p.Warnings)
		}
		p.Warnings = nil
		out, _ := json.Marshal(p)
		fmt.Println(string(out))
		return nil

	case "posture":
		return adminPostureCmd(ctx, c, rest)

	case "routes":
		var routes []api.Route
		if err := c.Do(ctx, "GET", api.PathRoutes, nil, &routes); err != nil {
			if code := agent.HTTPStatus(err); code == 404 || code == 405 {
				return errors.New("the control plane has no routes (older than ento 0.24)")
			}
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tNETWORKS\tGATEWAY\tNOTE")
		for _, r := range routes {
			nets := strings.Join(r.Networks, ",")
			if r.Exit {
				nets = "exit (all internet traffic)"
				if r.Default {
					nets = "exit (all internet traffic), used by default"
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, nets, r.Via, cell(strings.Join(r.Warnings, "; ")))
		}
		return w.Flush()

	case "dns":
		return adminDNSCmd(ctx, c, rest)

	case "updates":
		return adminUpdatesCmd(ctx, c, rest)

	case "route":
		op, args := sub(rest)
		switch op {
		case "add":
			const usage = "usage: ento admin route add NAME NETWORK[,NETWORK...] --via DEVICE | route add NAME --exit --via DEVICE [--default]"
			fs := flag.NewFlagSet("admin route add", flag.ExitOnError)
			via := fs.String("via", "", "the gateway device (its name, as peers shows it)")
			exit := fs.Bool("exit", false, "an exit: all internet traffic of the devices using it, no networks")
			dflt := fs.Bool("default", false, "with --exit: the devices allowed use it unless they turn it off")
			// NAME (and NETWORKS) come first: the flags follow them.
			if len(args) < 2 {
				return errors.New(usage)
			}
			req := api.Route{Name: args[0]}
			flags := args[1:]
			if !strings.HasPrefix(args[1], "-") {
				req.Networks, flags = splitList(args[1]), args[2:]
			}
			_ = fs.Parse(flags)
			if *via == "" || fs.NArg() > 0 || *exit == (len(req.Networks) > 0) {
				return errors.New(usage)
			}
			req.Via, req.Exit, req.Default = *via, *exit, *dflt
			var out api.Route
			if err := c.Do(ctx, "POST", api.PathRoutes, req, &out); err != nil {
				if req.Exit && agent.HTTPStatus(err) == 400 && strings.Contains(err.Error(), "between 1 and") {
					return errors.New("the control plane has no exits (older than ento 0.25)")
				}
				return err
			}
			printWarnings(out.Warnings)
			if out.Exit {
				how := "devices it allows choose it with `ento exit " + out.Name + "` (Android: in the app)"
				if out.Default {
					how = "devices it allows use it unless they turn it off (`ento exit off`)"
				}
				fmt.Printf("exit %s through %s; let a group use it with: ento admin allow GROUP route:%s; %s\n", out.Name, out.Via, out.Name, how)
				return nil
			}
			fmt.Printf("route %s: %s through %s; let a group reach it with: ento admin allow GROUP route:%s [--ports ...]\n",
				out.Name, strings.Join(out.Networks, ","), out.Via, out.Name)
			return nil
		case "delete":
			if len(args) != 1 {
				return errors.New("usage: ento admin route delete NAME")
			}
			return c.Do(ctx, "DELETE", api.PathRoutes+"/"+url.PathEscape(args[0]), nil, nil)
		}
		return errors.New("usage: ento admin route add NAME NETWORK[,NETWORK...] --via DEVICE | route add NAME --exit --via DEVICE [--default] | route delete NAME")

	case "disallow":
		id, err := oneID(rest)
		if err != nil {
			return err
		}
		return c.Do(ctx, "DELETE", fmt.Sprintf("%s/%d", api.PathPolicies, id), nil, nil)

	case "link", "links":
		return adminLinkCmd(ctx, c, cmd, rest)

	case "authority", "authorities":
		return adminAuthorityCmd(ctx, c, cmd, rest)
	}
	return errors.New("usage: ento admin [--link NAME] ui|token|tokens|revoke|peers|rename|confirm-name|approve|unapprove|signout|suspend|resume|groups|role|delete|policies|allow|policy|disallow|posture|route|routes|dns|link|links|authority|authorities|audit")
}

// knowsChecks makes sure the control plane knows posture checks (ento 0.13 and later) and has these;
// what names what was not added otherwise (a policy, a link).
func knowsChecks(ctx context.Context, c *agent.AdminClient, checks []string, what string) error {
	var have []api.PostureCheck
	if err := c.Do(ctx, "GET", api.PathPostureChecks, nil, &have); err != nil {
		if code := agent.HTTPStatus(err); code == 404 || code == 405 { // not found, method not allowed
			return fmt.Errorf("the control plane does not know posture checks (older than ento 0.13): "+
				"upgrade its control nodes first; no %s was added", what)
		}
		return err
	}
	for _, name := range checks {
		if !slices.ContainsFunc(have, func(h api.PostureCheck) bool { return h.Name == name }) {
			return fmt.Errorf("no posture check named %q (see `ento admin posture`)", name)
		}
	}
	return nil
}

// knowsLinkChecks makes sure the control plane can require posture checks of links (ento 0.14 and
// later; 0.13 knows checks but would create a link without them). It sends a change of a link that
// names nothing to change: 0.14 refuses it as invalid (400, before looking any link up, so whether a
// link "probe" exists does not matter and nothing changes), older control nodes have no such route
// (405).
func knowsLinkChecks(ctx context.Context, c *agent.AdminClient) error {
	err := c.Do(ctx, "PATCH", api.PathAdminLinks+"/probe", api.UpdateLinkRequest{}, nil)
	switch agent.HTTPStatus(err) {
	case 400:
		return nil
	case 404, 405:
		return errors.New("the control plane cannot require posture checks of links (older than ento 0.14): " +
			"upgrade every control node first; no link was added")
	}
	if err == nil {
		return errors.New("the control plane did not say whether it can require posture checks of links; no link was added")
	}
	return err
}

// printWarnings shows what the control plane warned of when a policy changed.
func printWarnings(w []string) {
	for _, x := range w {
		fmt.Fprintf(os.Stderr, "warning: %s\n", cell(x))
	}
}

// postureFlag takes --posture LIST (or --posture=LIST) out of args, wherever it is: nil when absent,
// empty for "none".
// ruleFlags takes --one-way, --two-way and --ports LIST out of args: the direction (nil: not given)
// and the port rules (nil: not given; ["all"] for all).
// ruleFlags reads --ports. Rules go one way (0.52): --one-way is what every rule is (accepted, for
// scripts written before), --two-way is refused.
// onFlag takes --on DEVICE_GROUP (the devices a rule's people are on, 0.53) from args.
func onFlag(args []string) (string, []string, error) {
	var on string
	var rest []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--on" || strings.HasPrefix(a, "--on="):
			v, ok := strings.CutPrefix(a, "--on=")
			if !ok {
				if i+1 >= len(args) {
					return "", nil, errors.New("--on needs a device group")
				}
				i++
				v = args[i]
			}
			on = v
		default:
			rest = append(rest, a)
		}
	}
	return on, rest, nil
}

func ruleFlags(args []string) ([]string, []string, error) {
	var rules, rest []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--one-way":
		case a == "--two-way":
			return nil, nil, errors.New("rules go one way (SOURCE opens, DESTINATION answers): for the other way add its own, ento admin allow DESTINATION SOURCE")
		case a == "--ports" || strings.HasPrefix(a, "--ports="):
			v, ok := strings.CutPrefix(a, "--ports=")
			if !ok {
				if i+1 >= len(args) {
					return nil, nil, errors.New("--ports needs a list of rules")
				}
				i++
				v = args[i]
			}
			c, err := ports.Canonical(splitList(v))
			if err != nil {
				return nil, nil, err
			}
			if len(c) == 0 {
				return nil, nil, errors.New("--ports needs a list of rules (or all)")
			}
			rules = c
		default:
			rest = append(rest, a)
		}
	}
	return rules, rest, nil
}

func postureFlag(args []string) ([]string, []string, error) {
	var checks, rest []string
	for i := 0; i < len(args); i++ {
		v, ok := strings.CutPrefix(args[i], "--posture=")
		if !ok && args[i] == "--posture" {
			if i+1 >= len(args) {
				return nil, nil, errors.New("--posture needs a list of checks")
			}
			i++
			v, ok = args[i], true
		}
		if !ok {
			rest = append(rest, args[i])
			continue
		}
		checks = []string{}
		if v != "none" {
			checks = splitList(v)
		}
	}
	return checks, rest, nil
}

// postureCell summarises a device's latest report for the peers table.
func postureCell(p api.PeerInfo) string {
	if p.Posture == nil {
		return "no report"
	}
	mark := func(v *bool, what string) string {
		switch {
		case v == nil:
			return what + "?"
		case *v:
			return what + "+"
		}
		return what + "-"
	}
	s := strings.Join([]string{mark(p.Posture.DiskEncryption, "enc"), mark(p.Posture.Firewall, "fw"),
		mark(p.Posture.SecureBoot, "sb"), mark(p.Posture.Antimalware, "av"), p.Posture.OS + " " + p.Posture.OSVersion}, " ")
	if t, err := time.Parse(time.RFC3339, p.PostureReportedAt); err == nil {
		s += fmt.Sprintf(" (%s ago)", api.HumanDuration(time.Since(t)))
	}
	return s
}

// failsCell lists the checks a device fails that a policy requires of it.
func failsCell(p api.PeerInfo) string {
	var out []string
	for _, r := range p.PostureChecks {
		if r.Required && !r.Passed {
			out = append(out, r.Check+": "+r.Reason)
		}
	}
	return strings.Join(out, "; ")
}

func adminPostureCmd(ctx context.Context, c *agent.AdminClient, args []string) error {
	op, rest := sub(args)
	switch op {
	case "", "list":
		var checks []api.PostureCheck
		if err := c.Do(ctx, "GET", api.PathPostureChecks, nil, &checks); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tDISK ENCRYPTION\tFIREWALL\tSECURE BOOT\tANTI-MALWARE\tMINIMUM SYSTEM\tPATCH AGE\tMAX AGE")
		for _, ch := range checks {
			var minOS, patch []string
			for _, k := range slices.Sorted(maps.Keys(ch.MinOS)) {
				minOS = append(minOS, k+"="+ch.MinOS[k])
			}
			for _, k := range slices.Sorted(maps.Keys(ch.MaxPatchAgeDays)) {
				patch = append(patch, fmt.Sprintf("%s=%dd", k, ch.MaxPatchAgeDays[k]))
			}
			fmt.Fprintf(w, "%s\t%v\t%v\t%v\t%v\t%s\t%s\t%s\n", cell(ch.Name), ch.DiskEncryption, ch.Firewall, ch.SecureBoot, ch.Antimalware,
				cell(strings.Join(minOS, ",")), cell(strings.Join(patch, ",")), api.HumanDuration(time.Duration(ch.MaxAgeSeconds)*time.Second))
		}
		return w.Flush()
	case "add":
		fs := flag.NewFlagSet("admin posture add", flag.ExitOnError)
		disk := fs.Bool("disk-encryption", false, "the system disk must be encrypted (LUKS, FileVault, BitLocker, Android)")
		firewall := fs.Bool("firewall", false, "the firewall must filter incoming connections")
		secureBoot := fs.Bool("secure-boot", false, "the device must boot with UEFI Secure Boot (Android: verified boot with the bootloader locked, as the phone's secure hardware attests it)")
		antimalware := fs.Bool("antimalware", false, "real-time anti-malware must be on (Windows Security or Defender, macOS XProtect, a known Linux scanner)")
		minOS := fs.String("min-os", "", "oldest system versions accepted, e.g. linux=6.1,windows=10.0.22631,darwin=14.0,android=13 (Linux: the kernel release; Windows: 10.0.BUILD, also for Windows 11, which is 10.0.22000 and later; systems not named are not limited)")
		maxAge := fs.Duration("max-age", 30*time.Minute, "how old the device's latest report may be (agents report every 10 minutes)")
		maxPatch := fs.String("max-patch-age", "", "how old the security patch may be, per system: android=90d (at least 45 days; the oldest of the system's, vendor's and boot image's patch levels the phone attests)")
		name, flags := sub(rest)
		_ = fs.Parse(flags)
		if name == "" || strings.HasPrefix(name, "-") {
			return errors.New("usage: ento admin posture add NAME [flags]")
		}
		req := api.PostureCheck{Name: name, DiskEncryption: *disk, Firewall: *firewall, SecureBoot: *secureBoot,
			Antimalware: *antimalware, MaxAgeSeconds: int(maxAge.Seconds())}
		for _, item := range splitList(*maxPatch) {
			k, v, ok := strings.Cut(item, "=")
			days, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(v), "d"))
			if !ok || err != nil || days <= 0 {
				return fmt.Errorf("--max-patch-age: %q is not SYSTEM=DAYS (e.g. android=90d)", item)
			}
			if req.MaxPatchAgeDays == nil {
				req.MaxPatchAgeDays = map[string]int{}
			}
			req.MaxPatchAgeDays[strings.TrimSpace(k)] = days
		}
		for _, item := range splitList(*minOS) {
			k, v, ok := strings.Cut(item, "=")
			if !ok {
				return fmt.Errorf("--min-os: %q is not SYSTEM=VERSION", item)
			}
			if req.MinOS == nil {
				req.MinOS = map[string]string{}
			}
			if k = strings.TrimSpace(k); k == "macos" {
				k = "darwin"
			}
			req.MinOS[k] = strings.TrimSpace(v)
		}
		var out api.PostureCheck
		if err := c.Do(ctx, "POST", api.PathPostureChecks, req, &out); err != nil {
			return err
		}
		if len(req.MaxPatchAgeDays) > 0 && len(out.MaxPatchAgeDays) == 0 {
			// Never leave that unsaid: the check would pass phones whatever their patch level.
			return fmt.Errorf("the control plane ignored --max-patch-age (older than ento 0.30?): check %s was added WITHOUT it; "+
				"delete it with `ento admin posture delete %s`, upgrade every control node and add it again", out.Name, out.Name)
		}
		fmt.Fprintf(os.Stderr, "posture check %s added; require it with `ento admin allow SOURCE DESTINATION --posture %s` or `ento admin policy ID --posture %s`\n",
			out.Name, out.Name, out.Name)
		return nil
	case "delete":
		if len(rest) != 1 {
			return errors.New("usage: ento admin posture delete NAME")
		}
		return c.Do(ctx, "DELETE", api.PathPostureChecks+"/"+rest[0], nil, nil)
	}
	return errors.New("usage: ento admin posture [list] | add NAME [flags] | delete NAME")
}

func adminLinkCmd(ctx context.Context, c *agent.AdminClient, cmd string, args []string) error {
	op, rest := sub(args)
	if cmd == "links" {
		op = "list"
	}
	switch op {
	case "list":
		var links []api.LinkInfo
		if err := c.Do(ctx, "GET", api.PathAdminLinks, nil, &links); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tGROUPS\tGRANT\tTTL\tPOSTURE\tTOKEN\tAUTHORITY KEY")
		for _, l := range links {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%v\t%s\n", cell(l.Name), cell(strings.Join(l.Groups, ",")), cell(strings.Join(l.Grant, ",")),
				time.Duration(l.TTLSeconds)*time.Second, cell(strings.Join(l.Posture, ",")), l.HasToken, l.PublicKey)
		}
		return w.Flush()
	case "create":
		checks, rest, err := postureFlag(rest)
		if err != nil {
			return err
		}
		fs := flag.NewFlagSet("admin link create", flag.ExitOnError)
		groups := fs.String("groups", "", "comma-separated groups of this network whose devices may join")
		grant := fs.String("grant", "", "comma-separated groups requested for them in the linked network")
		ttl := fs.Duration("ttl", 12*time.Hour, "lifetime of each credential (devices renew them)")
		name, flags := sub(rest)
		_ = fs.Parse(flags)
		if len(checks) > 0 {
			// A control node older than 0.14 would create the link and ignore its checks: ask first
			// whether it can require checks of links, and whether these exist; the answer is looked
			// at too (another control node may answer the creation).
			if err := knowsLinkChecks(ctx, c); err != nil {
				return err
			}
			if err := knowsChecks(ctx, c, checks, "link"); err != nil {
				return err
			}
		}
		var l api.LinkInfo
		if err := c.Do(ctx, "POST", api.PathAdminLinks, api.CreateLinkRequest{Name: name, Groups: splitList(*groups),
			Grant: splitList(*grant), TTLSeconds: int(ttl.Seconds()), Posture: checks}, &l); err != nil {
			return err
		}
		if len(checks) > 0 && len(l.Posture) == 0 {
			// Never leave that unsaid: its devices would get credentials whatever their posture.
			return fmt.Errorf("the control plane ignored --posture (older than ento 0.14?): link %s was created WITHOUT checks; "+
				"delete it with `ento admin link delete %s`, or upgrade every control node and run `ento admin link update %s --posture %s`",
				l.Name, l.Name, l.Name, strings.Join(checks, ","))
		}
		fmt.Fprintf(os.Stderr, "link %s created; register this authority key in the linked network:\n", l.Name)
		fmt.Println(l.PublicKey)
		return nil
	case "update":
		checks, args, err := postureFlag(rest)
		if err != nil || len(args) != 1 || checks == nil {
			return errors.New("usage: ento admin link update NAME --posture CHECK[,CHECK...]|none")
		}
		var l api.LinkInfo
		err = c.Do(ctx, "PATCH", api.PathAdminLinks+"/"+args[0], api.UpdateLinkRequest{Posture: &checks}, &l)
		if code := agent.HTTPStatus(err); code == 405 {
			return errors.New("the control plane cannot change links (older than ento 0.14): upgrade every control node first")
		}
		if err != nil {
			return err
		}
		out, _ := json.Marshal(l)
		fmt.Println(string(out))
		return nil
	case "token":
		fs := flag.NewFlagSet("admin link token", flag.ExitOnError)
		file := fs.String("token-file", "", "read the linked network's token from this file")
		stdin := fs.Bool("token-stdin", false, "read the token from stdin")
		name, flags := sub(rest)
		_ = fs.Parse(flags)
		tok, err := readToken(*file, *stdin)
		if err != nil {
			return err
		}
		if tok == "" {
			return errors.New("no token: use --token-file, --token-stdin or ENTO_TOKEN")
		}
		return c.Do(ctx, "PUT", api.PathAdminLinks+"/"+name+"/token", api.SetLinkTokenRequest{Token: tok}, nil)
	case "delete":
		if len(rest) != 1 {
			return errors.New("usage: ento admin link delete NAME")
		}
		return c.Do(ctx, "DELETE", api.PathAdminLinks+"/"+rest[0], nil, nil)
	}
	return errors.New("usage: ento admin link create|update|token|delete NAME ... | ento admin links")
}

func adminAuthorityCmd(ctx context.Context, c *agent.AdminClient, cmd string, args []string) error {
	op, rest := sub(args)
	if cmd == "authorities" {
		op = "list"
	}
	switch op {
	case "list":
		var auths []api.AuthorityInfo
		if err := c.Do(ctx, "GET", api.PathAuthorities, nil, &auths); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tGROUPS\tMAX TTL\tDEVICES\tSTATE\tKEY")
		for _, a := range auths {
			state := "active"
			if a.Suspended {
				state = "suspended"
			}
			devices := strconv.Itoa(a.Devices)
			if a.MaxDevices > 0 {
				devices += "/" + strconv.Itoa(a.MaxDevices)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", a.Name, strings.Join(a.Groups, ","),
				time.Duration(a.MaxTTLSeconds)*time.Second, devices, state, a.PublicKey)
		}
		return w.Flush()
	case "add":
		fs := flag.NewFlagSet("admin authority add", flag.ExitOnError)
		key := fs.String("key", "", "the authority's public key (entoa1:...), from `ento admin link create` in its network")
		groups := fs.String("groups", "", "comma-separated groups the authority may assign (devices get them as NAME:GROUP)")
		maxTTL := fs.Duration("max-ttl", 12*time.Hour, "longest approval a single credential may give")
		maxDevices := fs.Int("max-devices", 0, "how many of its devices may be in this network at a time (0: no limit)")
		out := fs.String("out", "", "write the authority's enrollment token to this file (mode 0600) instead of stdout")
		name, flags := sub(rest)
		_ = fs.Parse(flags)
		var res api.CreateAuthorityResponse
		if err := c.Do(ctx, "POST", api.PathAuthorities, api.CreateAuthorityRequest{Name: name, PublicKey: *key,
			Groups: splitList(*groups), MaxTTLSeconds: int(maxTTL.Seconds()), MaxDevices: *maxDevices}, &res); err != nil {
			return err
		}
		return emitAuthorityToken(name, res.Token, *out, "registered")
	case "token":
		fs := flag.NewFlagSet("admin authority token", flag.ExitOnError)
		out := fs.String("out", "", "write the new enrollment token to this file (mode 0600) instead of stdout")
		name, flags := sub(rest)
		_ = fs.Parse(flags)
		if name == "" {
			return errors.New("usage: ento admin authority token NAME [--out FILE]")
		}
		var res api.RotateAuthorityTokenResponse
		if err := c.Do(ctx, "POST", api.PathAuthorities+"/"+name+"/token", nil, &res); err != nil {
			return err
		}
		return emitAuthorityToken(name, res.Token, *out, "has a new enrollment token (the previous one no longer works)")
	case "limit":
		if len(rest) != 2 {
			return errors.New("usage: ento admin authority limit NAME N   (0: no limit)")
		}
		n, err := strconv.Atoi(rest[1])
		if err != nil || n < 0 {
			return errors.New("the limit is a number of devices, 0 for none")
		}
		return c.Do(ctx, "PUT", api.PathAuthorities+"/"+rest[0]+"/limit", api.AuthorityLimitRequest{MaxDevices: n}, nil)
	case "delete":
		if len(rest) != 1 {
			return errors.New("usage: ento admin authority delete NAME")
		}
		return c.Do(ctx, "DELETE", api.PathAuthorities+"/"+rest[0], nil, nil)
	case "suspend", "resume":
		if len(rest) != 1 {
			return fmt.Errorf("usage: ento admin authority %s NAME", op)
		}
		suspend := op == "suspend"
		return c.Do(ctx, "PATCH", api.PathAuthorities+"/"+rest[0], api.UpdateAuthorityRequest{Suspended: &suspend}, nil)
	}
	return errors.New("usage: ento admin authority add|token|limit|suspend|resume|delete NAME ... | ento admin authorities")
}

// emitAuthorityToken hands out an authority's enrollment token: to a file, or on stdout.
func emitAuthorityToken(name, tok, out, what string) error {
	if out == "" {
		fmt.Println(tok)
		return nil
	}
	if err := os.WriteFile(out, []byte(tok+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "authority %s %s; hand %s to its network (`ento admin link token`)\n", name, what, out)
	return nil
}

func oneID(args []string) (int64, error) {
	if len(args) != 1 {
		return 0, errors.New("expected one peer or policy ID")
	}
	return strconv.ParseInt(args[0], 10, 64)
}

func parseHosts(s string) []api.Host {
	var out []api.Host
	for _, item := range splitList(s) {
		if name, addr, ok := strings.Cut(item, "="); ok {
			out = append(out, api.Host{Name: strings.TrimSpace(name), Address: strings.TrimSpace(addr)})
		}
	}
	return out
}

// agentApprove asks for a sign-in approval and waits for it: exit 0 approved, 1 denied, 2 expired,
// 3 unavailable (anything that keeps it from being asked or answered). The number goes to stdout
// at once, for pam_exec to show.
func agentApprove(ctx context.Context, cfg *agent.Config, user, service string, timeout time.Duration, network string) error {
	timeout = min(max(timeout, 10*time.Second), 2*time.Minute)
	// A control plane that does not answer within seconds will not: fall through at once rather
	// than hold up every sudo (pam_exec waits for this step).
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	res, err := agent.RequestApproval(reqCtx, *cfg, user, service, timeout)
	cancel()
	if err != nil {
		return exitCode{3, "sign-in approval unavailable: " + err.Error()}
	}
	fmt.Printf("Approve this sign-in%s on your phone or other device: pick %d\n", network, res.Number)
	_ = os.Stdout.Sync()
	waitCtx, cancel := context.WithTimeout(ctx, timeout+10*time.Second)
	defer cancel()
	state, err := agent.WaitApproval(waitCtx, *cfg, res.ID)
	switch {
	case err != nil && waitCtx.Err() != nil:
		return exitCode{2, "no answer in time"}
	case err != nil:
		return exitCode{3, "sign-in approval unavailable: " + err.Error()}
	case state == "approved":
		fmt.Println("Approved.")
		return nil
	case state == "denied":
		return exitCode{1, "denied"}
	case state == "expired":
		return exitCode{2, "no answer in time"}
	}
	return exitCode{3, "unexpected answer: " + state}
}

// approvalsCmd lists the sign-ins waiting for this device's person, or answers one.
func approvalsCmd(ctx context.Context, args []string) error {
	op, rest := sub(args)
	fs := flag.NewFlagSet("agent approvals", flag.ExitOnError)
	cfg := agentFlags(fs)
	network := networkFlag(fs)
	deny := fs.Bool("deny", false, "answer: deny the sign-in")
	wait := fs.Duration("wait", 0, "list: wait up to this long for one (at most 25s)")
	if op != "" && op != "answer" {
		rest = args
		op = ""
	}
	_ = fs.Parse(rest)
	baseDir := cfg.StateDir
	if err := useNetwork(cfg, *network); err != nil {
		return err
	}
	if op == "" && *network == "" && severalNetworks(baseDir) {
		return approvalsEveryNetwork(ctx, *cfg, *wait)
	}
	switch op {
	case "":
		list, err := agent.PendingApprovals(ctx, *cfg, *wait)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			fmt.Println("no sign-in waits for your approval")
			return nil
		}
		for _, a := range list {
			fmt.Printf("%s  %s on %s (%s), numbers %v, until %s\n", a.ID, a.User, a.Device, a.Service, a.Choices, a.ExpiresAt)
		}
		fmt.Println("answer with: ento agent approvals answer ID NUMBER (the number the device shows; answer --deny ID NUMBER refuses)")
		return nil
	case "answer":
		if fs.NArg() != 2 {
			return errors.New("usage: ento agent approvals answer [--deny] ID NUMBER")
		}
		n, err := strconv.Atoi(fs.Arg(1))
		if err != nil {
			return errors.New("NUMBER is the number the device shows")
		}
		state, err := agent.AnswerApproval(ctx, *cfg, fs.Arg(0), n, !*deny)
		if err != nil {
			return err
		}
		fmt.Println(state)
		return nil
	}
	return nil
}

// exitLine describes an exit offered to the device.
func exitLine(e agent.RunningExit) string {
	switch {
	case e.InUse:
		return fmt.Sprintf("%s through %s: IN USE, all internet traffic goes through it (ento exit off)", e.Route, e.Via)
	case e.Default:
		return fmt.Sprintf("%s through %s: offered, used by default (ento exit default)", e.Route, e.Via)
	}
	return fmt.Sprintf("%s through %s: offered (ento exit %s)", e.Route, e.Via, e.Route)
}

// showExits prints the device's choice of exit and the exits offered to it.
func showExits(stateDir string) error {
	choice := agent.ExitChoice(stateDir)
	switch choice {
	case "":
		fmt.Println("choice: the exit used by default, if one is offered")
	case agent.ExitOff:
		fmt.Println("choice: off (no exit)")
	default:
		fmt.Printf("choice: %s\n", choice)
	}
	r, running := agent.RunningAgent(stateDir)
	if !running {
		fmt.Println("the agent is not running")
		return nil
	}
	if len(r.Exits) == 0 {
		fmt.Println("no exit is offered to this device")
	}
	for _, e := range r.Exits {
		fmt.Println(exitLine(e))
	}
	return nil
}

// awaitExit waits (at most 10 s) for the running agent to apply a choice of exit and says what it
// did.
func awaitExit(stateDir, choice string) error {
	r, running := agent.RunningAgent(stateDir)
	if !running {
		fmt.Println("choice kept; the agent is not running, it applies it when it starts")
		return nil
	}
	want := func(r agent.Running) (agent.RunningExit, bool) {
		for _, e := range r.Exits {
			if choice == e.Route || choice == "" && e.Default {
				return e, true
			}
		}
		return agent.RunningExit{}, false
	}
	if choice != agent.ExitOff {
		if _, ok := want(r); !ok {
			if choice == "" {
				fmt.Println("choice kept: no exit used by default is offered to this device now")
			} else {
				fmt.Printf("choice kept: exit %s is not offered to this device now (ento status lists those that are); it is used once it is\n", choice)
			}
			return nil
		}
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		r, _ = agent.RunningAgent(stateDir)
		inUse := slices.ContainsFunc(r.Exits, func(e agent.RunningExit) bool { return e.InUse })
		if e, ok := want(r); choice != agent.ExitOff && ok && e.InUse {
			fmt.Println("exit " + exitLine(e))
			return nil
		} else if choice == agent.ExitOff && !inUse {
			fmt.Println("no exit: traffic takes its normal path")
			return nil
		}
	}
	return errors.New("the agent has not applied it yet: see its log (journalctl -u ento-agent)")
}

// adminDNSCmd lists and changes the network's internal DNS.
func adminDNSCmd(ctx context.Context, c *agent.AdminClient, rest []string) error {
	const usage = "usage: ento admin dns [domain NAME | add NAME ADDRESS | delete NAME | forward ZONE SERVER[,SERVER...] | unforward ZONE]"
	old := func(err error) error {
		if code := agent.HTTPStatus(err); code == 404 || code == 405 {
			return errors.New("the control plane has no internal DNS (older than ento 0.26)")
		}
		return err
	}
	op, args := sub(rest)
	switch op {
	case "":
		var d api.DNSAdmin
		if err := c.Do(ctx, "GET", api.PathDNS, nil, &d); err != nil {
			return old(err)
		}
		if d.Domain == "" {
			fmt.Println("this network has no internal DNS yet: give it a domain (ento admin dns domain NAME, e.g. corp.internal)")
			return nil
		}
		records, forwards := d.Records, d.Forwards
		fmt.Printf("domain %s: every approved device is <device name>.%s (ento admin peers lists them)\n", d.Domain, d.Domain)
		if len(records) == 0 && len(forwards) == 0 {
			fmt.Println("no names added and no zones forwarded (ento admin dns add NAME ADDRESS, dns forward ZONE SERVER)")
			return nil
		}
		fmt.Println("names added:")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tADDRESS\tNOTE")
		for _, r := range records {
			fmt.Fprintf(w, "%s\t%s\t%s\n", cell(r.Name), r.Address, cell(strings.Join(r.Warnings, "; ")))
		}
		if len(forwards) > 0 {
			fmt.Fprintln(w, "\nZONE\tSERVERS\t")
			for _, f := range forwards {
				fmt.Fprintf(w, "%s\t%s\t\n", cell(f.Zone), strings.Join(f.Servers, ","))
			}
		}
		return w.Flush()
	case "domain":
		if len(args) != 1 {
			return errors.New(usage)
		}
		var out api.DNSDomain
		if err := c.Do(ctx, "PUT", api.PathDNSDomain, api.DNSDomain{Domain: args[0]}, &out); err != nil {
			if code := agent.HTTPStatus(err); code == 404 || code == 405 {
				return errors.New("the control plane sets its domain only by --dns-domain (older than ento 0.55)")
			}
			return err
		}
		fmt.Printf("domain %s: every approved device is <device name>.%s from its next map\n", out.Domain, out.Domain)
		return nil
	case "add":
		if len(args) != 2 {
			return errors.New(usage)
		}
		var out api.DNSRecord
		if err := c.Do(ctx, "POST", api.PathDNSRecords, api.DNSRecord{Name: args[0], Address: args[1]}, &out); err != nil {
			return old(err)
		}
		fmt.Printf("%s is %s for the devices that reach it\n", out.Name, out.Address)
		return nil
	case "delete":
		if len(args) != 1 {
			return errors.New(usage)
		}
		return old(c.Do(ctx, "DELETE", api.PathDNSRecords+"/"+url.PathEscape(args[0]), nil, nil))
	case "forward":
		if len(args) != 2 {
			return errors.New(usage)
		}
		var out api.DNSForward
		if err := c.Do(ctx, "POST", api.PathDNSForwards, api.DNSForward{Zone: args[0], Servers: splitList(args[1])}, &out); err != nil {
			return old(err)
		}
		fmt.Printf("names in %s are asked of %s (by the devices that reach it)\n", out.Zone, strings.Join(out.Servers, ", "))
		return nil
	case "unforward":
		if len(args) != 1 {
			return errors.New(usage)
		}
		return old(c.Do(ctx, "DELETE", api.PathDNSForwards+"/"+url.PathEscape(args[0]), nil, nil))
	}
	return errors.New(usage)
}

// personAware reports whether an agent version announces the person layer (0.27 and later).
func personAware(version string) bool {
	var major, minor int
	if _, err := fmt.Sscanf(version, "%d.%d", &major, &minor); err != nil {
		return true
	}
	return major > 0 || minor >= 27
}

// localTime shows an RFC 3339 time in the local zone, to the minute (as given when it does not parse).
func localTime(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return t.Local().Format("2006-01-02 15:04")
}
