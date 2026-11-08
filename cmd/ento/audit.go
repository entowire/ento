package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"entowire.com/ento/internal/agent"
	"entowire.com/ento/internal/api"
)

// auditCmd lists the network's audit (0.53): ento admin audit [--action A] [--result R]
// [--search TEXT] [--since DURATION|TIME] [--limit N] [--csv].
func auditCmd(ctx context.Context, c *agent.AdminClient, args []string) error {
	fs := flag.NewFlagSet("admin audit", flag.ContinueOnError)
	action := fs.String("action", "", "only this action (e.g. policy_added)")
	result := fs.String("result", "", "only this result: ok, denied or failed")
	search := fs.String("search", "", "only entries with this text in any field")
	since := fs.String("since", "", "only entries since then: a duration (24h) or a time (RFC 3339)")
	limit := fs.Int("limit", 50, "at most this many entries (with --csv: every matching one)")
	asCSV := fs.Bool("csv", false, "every matching entry as CSV, oldest last")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("usage: ento admin audit [--action A] [--result ok|denied|failed] [--search TEXT] [--since 24h|TIME] [--limit N] [--csv]")
	}
	q := url.Values{}
	for k, v := range map[string]string{"action": *action, "result": *result, "q": *search} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if *since != "" {
		t, err := time.Parse(time.RFC3339, *since)
		if err != nil {
			d, derr := time.ParseDuration(*since)
			if derr != nil {
				return errors.New("--since: a duration (24h) or a time (2026-11-08T09:00:00Z)")
			}
			t = time.Now().Add(-d)
		}
		q.Set("since", t.UTC().Format(time.RFC3339))
	}
	page := func(before int64, n int) (api.AuditPage, error) {
		q.Set("limit", strconv.Itoa(n))
		if before > 0 {
			q.Set("before", strconv.FormatInt(before, 10))
		}
		var p api.AuditPage
		err := c.Do(ctx, "GET", api.PathAudit+"?"+q.Encode(), nil, &p)
		return p, err
	}
	if *asCSV {
		w := csv.NewWriter(os.Stdout)
		_ = w.Write([]string{"id", "at", "node", "action", "device", "person", "from", "target", "result"})
		var before int64
		for n := 0; n < api.MaxAuditExport; {
			p, err := page(before, 1000)
			if err != nil {
				return err
			}
			for _, e := range p.Entries {
				_ = w.Write([]string{strconv.FormatInt(e.ID, 10), e.At, e.Node, e.Action, e.Device, e.Person, e.From, e.Target, e.Result})
			}
			n += len(p.Entries)
			if !p.More || len(p.Entries) == 0 {
				break
			}
			before = p.Entries[len(p.Entries)-1].ID
		}
		w.Flush()
		return w.Error()
	}
	if *limit < 1 || *limit > 1000 {
		return errors.New("--limit: 1 to 1000")
	}
	p, err := page(0, *limit)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "WHEN\tNODE\tACTION\tBY\tTARGET\tRESULT")
	for _, e := range p.Entries {
		at := e.At
		if t, err := time.Parse(time.RFC3339Nano, e.At); err == nil {
			at = t.Local().Format("2006-01-02 15:04:05")
		}
		by := e.Device
		if e.Person != "" {
			by += " (" + e.Person + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", at, e.Node, e.Action, cell(by), cell(strings.TrimSpace(e.Target)), e.Result)
	}
	if p.More {
		fmt.Fprintf(w, "(older entries too: --limit, --since or --csv)\n")
	}
	return w.Flush()
}

// sourceWord is a rule's source as one word for `ento admin policies`: WHO@DEVICES for people on a
// device group (0.53: engineers@laptops, *signed-in@laptops), else the source as before.
func sourceWord(p api.Policy) string {
	if p.On != "" && p.Who != "" && p.Who != "*" {
		return p.Who + "@" + strings.TrimPrefix(p.On, "device:")
	}
	return p.Source
}
