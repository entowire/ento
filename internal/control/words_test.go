package control

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/token"
)

// Enrollment by words: an operator's words and the network record are all a device needs; it
// rebuilds the token the control node derived (secret, temporary key, enrollment address) and
// enrolls with it, once.
func TestEnrollmentByWords(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, st := startTestNetwork(t, ctx, "100.64.0.0/16")
	admin := adminOf(t, ctx, srv, st, "ops-laptop", "staff")

	var rec api.NetworkRecordResponse
	if code := admin.do(t, "GET", api.PathRecord, nil, &rec); code != 200 {
		t.Fatalf("record: HTTP %d", code)
	}
	r, err := token.ParseRecord(rec.Record)
	if err != nil || r.Fingerprint() != rec.Fingerprint || r.Network.String() != "100.64.0.0/16" || len(r.Controls) != 1 {
		t.Fatalf("record %q: %v", rec.Record, err)
	}

	var res api.CreateTokenResponse
	if code := admin.do(t, "POST", api.PathTokens, api.CreateTokenRequest{Groups: []string{"servers"}, Approve: true,
		Name: "web-2", Words: true}, &res); code != http.StatusCreated {
		t.Fatalf("words token: HTTP %d", code)
	}
	if res.Token != "" || res.Fingerprint != rec.Fingerprint || len(strings.Fields(res.Words)) != token.WordCount {
		t.Fatalf("response: %+v", res)
	}
	w, err := token.ParseWords(strings.ToUpper(strings.ReplaceAll(res.Words, " ", "-")))
	if err != nil {
		t.Fatal(err)
	}
	tok, err := r.Token(w)
	if err != nil {
		t.Fatal(err)
	}
	s, err := tok.Encode()
	if err != nil {
		t.Fatal(err)
	}
	srv.checkVersion(ctx)            // the temporary peer
	_, red := enroll(t, s, "laptop") // also checks that a second use is refused
	p, err := st.PeerByAddress(ctx, netip.MustParseAddr(red.Address))
	if err != nil || p.Hostname != "web-2" || !p.Approved || !slices.Equal(p.Groups, []string{"device:servers"}) {
		t.Fatalf("enrolled as %+v (%v)", p, err)
	}

	// Words are good for a day at most; a device that is no operator gets no record.
	if code := admin.do(t, "POST", api.PathTokens, api.CreateTokenRequest{Words: true, TTLSeconds: 2 * 86400}, nil); code != http.StatusBadRequest {
		t.Fatalf("words for two days: HTTP %d", code)
	}
	tok2, _, _ := IssueToken(ctx, st, TokenOptions{Approve: true, Groups: []string{"laptops"}})
	srv.checkVersion(ctx)
	plain, _ := enroll(t, tok2, "plain")
	if code := plain.do(t, "GET", api.PathRecord, nil, nil); code != http.StatusForbidden {
		t.Fatalf("record for an ordinary device: HTTP %d", code)
	}
}
