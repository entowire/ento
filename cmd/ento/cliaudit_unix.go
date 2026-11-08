//go:build !windows

package main

import (
	"context"
	"fmt"
	"log/syslog"
	"os"
	"strings"
	"time"

	"entowire.com/ento/internal/store"
)

// cliAudit logs a change made through ento control (straight in the database) to the system log,
// as the control nodes log theirs:
//
//	audit: action=control_cli by="alice (cli)" from=local target="ento control allow servers servers" result=ok
//
// "by" is whoever ran it (the user behind sudo). The arguments name no secret (tokens are printed,
// never taken as arguments). The line also goes into the network's audit, in the database the
func cliAudit(args []string, err error) {
	who := os.Getenv("SUDO_USER")
	if who == "" {
		who = os.Getenv("USER")
	}
	if who == "" {
		who = fmt.Sprint(os.Getuid())
	}
	result := "ok"
	if err != nil {
		result = "failed"
	}
	clean := strings.NewReplacer(`"`, "'", "\n", " ")
	line := fmt.Sprintf("audit: action=control_cli by=%q from=local target=%q result=%s",
		clean.Replace(who+" (cli)"), clean.Replace("ento control "+strings.Join(args, " ")), result)
	if w, e := syslog.New(syslog.LOG_AUTH|syslog.LOG_NOTICE, "ento"); e == nil {
		w.Notice(line)
		w.Close()
	}
	if storeNetwork == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, _, e := openStore(ctx, storeNetwork)
	if e != nil {
		fmt.Fprintf(os.Stderr, "ento: the network's audit not written (only the system log): %v\n", e)
		return
	}
	defer st.Close()
	host, _ := os.Hostname()
	if e := st.AddAudit(ctx, store.AuditEntry{At: time.Now().UTC(), Node: host, Action: "control_cli", Device: "command line",
		Person: clean.Replace(who), From: "local", Target: clean.Replace("ento control " + strings.Join(args, " ")), Result: result}); e != nil {
		fmt.Fprintf(os.Stderr, "ento: the network's audit not written (only the system log): %v\n", e)
	}
}
