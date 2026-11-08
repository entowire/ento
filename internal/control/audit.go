package control

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"entowire.com/ento/internal/api"
	"entowire.com/ento/internal/store"
)

// auditWrite bounds how long one audit entry may take to reach the database.
const auditWrite = 3 * time.Second

// audit logs a security-relevant action in one line a SIEM can parse:
//
//	audit: action=peer_deleted by="laptop (alice@example.com)" from=100.64.1.2 target="peer 7 web-1" result=ok
//
// "by" is the device (and its SSO user) that made the request, "from" its overlay address. Values
// never contain secrets. The entry also goes into the network's audit in the database (0.53),
// which every control node shares and the dashboard's Activity shows; when the database does not
// take it, the journal line stays the record, and a second line says so.
func (s *Server) audit(r *http.Request, by *store.Peer, action, target, result string) {
	who, from := "-", "-"
	device, person := "-", ""
	if by != nil {
		who, device, person = by.Hostname, by.Hostname, by.UserName
		if by.UserName != "" {
			who += " (" + by.UserName + ")"
		}
		from = by.Address.String()
	} else if r != nil {
		if a, ok := caller(r); ok {
			from = a.String()
		}
	}
	s.cfg.Logf("audit: action=%s by=%q from=%s target=%q result=%s", action, clean(who), from, clean(target), result)
	if s.cfg.Store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), auditWrite)
	defer cancel()
	e := store.AuditEntry{At: time.Now().UTC(), Node: s.cfg.Name, Action: action, Device: clean(device), Person: clean(person),
		From: from, Target: clean(target), Result: result}
	if err := s.cfg.Store.AddAudit(ctx, e); err != nil {
		s.cfg.Logf("audit entry not stored in the database (this line is its record): action=%s: %v", action, err)
	}
}

func clean(s string) string { return strings.NewReplacer("\"", "'", "\n", " ").Replace(s) }

func peerLabel(p store.Peer) string { return fmt.Sprintf("peer %d %s %s", p.ID, p.Hostname, p.Address) }

func apiAudit(e store.AuditEntry) api.AuditEntry {
	return api.AuditEntry{ID: e.ID, At: e.At.UTC().Format(time.RFC3339Nano), Node: e.Node, Action: e.Action, Device: e.Device,
		Person: e.Person, From: e.From, Target: e.Target, Result: e.Result}
}

// auditQuery reads an audit query from a request's parameters (api.PathAudit).
func auditQuery(r *http.Request) (store.AuditQuery, error) {
	v := r.URL.Query()
	q := store.AuditQuery{Action: v.Get("action"), Result: v.Get("result"), Text: v.Get("q"), Limit: 100}
	if len(q.Text) > 200 || len(q.Action) > 64 {
		return q, errors.New("the search is too long")
	}
	if b := v.Get("before"); b != "" {
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil || n < 1 {
			return q, errors.New("before: an entry's ID")
		}
		q.Before = n
	}
	if l := v.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > store.MaxAuditPage {
			return q, fmt.Errorf("limit: 1 to %d", store.MaxAuditPage)
		}
		q.Limit = n
	}
	if since := v.Get("since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			return q, errors.New("since: a time in RFC 3339")
		}
		q.Since = t
	}
	return q, nil
}

// 4.7). An export is itself audited.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, self store.Peer) {
	q, err := auditQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if r.URL.Query().Get("format") == "csv" {
		s.exportAudit(w, r, self, q)
		return
	}
	want := q.Limit
	q.Limit++ // one more says whether there are more
	entries, err := s.cfg.Store.Audit(r.Context(), q)
	if err != nil {
		s.respondStoreErr(w, err)
		return
	}
	out := api.AuditPage{Entries: []api.AuditEntry{}}
	if len(entries) > want {
		entries, out.More = entries[:want], true
	}
	for _, e := range entries {
		out.Entries = append(out.Entries, apiAudit(e))
	}
	writeJSON(w, http.StatusOK, out)
}

// exportAudit writes every entry the query matches (up to api.MaxAuditExport), newest first, as CSV.
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request, self store.Peer, q store.AuditQuery) {
	s.audit(r, &self, "audit_exported", fmt.Sprintf("action=%s result=%s q=%q since=%s", q.Action, q.Result, q.Text, q.Since.Format(time.RFC3339)), "ok")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="audit-%s.csv"`, time.Now().UTC().Format("2006-01-02")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "at", "node", "action", "device", "person", "from", "target", "result"})
	q.Limit = store.MaxAuditPage
	for n := 0; n < api.MaxAuditExport; {
		entries, err := s.cfg.Store.Audit(r.Context(), q)
		if err != nil {
			_ = cw.Write([]string{"", "", "", "export_incomplete", "", "", "", err.Error(), "failed"})
			break
		}
		for _, e := range entries {
			_ = cw.Write([]string{strconv.FormatInt(e.ID, 10), e.At.UTC().Format(time.RFC3339Nano), e.Node, e.Action, e.Device, e.Person,
				e.From, e.Target, e.Result})
		}
		n += len(entries)
		if len(entries) < q.Limit {
			break
		}
		q.Before = entries[len(entries)-1].ID
	}
	cw.Flush()
}
