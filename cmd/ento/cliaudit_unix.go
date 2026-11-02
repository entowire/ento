//go:build !windows

package main

import (
	"fmt"
	"log/syslog"
	"os"
	"strings"
)

// cliAudit logs a change made through ento control (straight in the database) to the system log,
// as the control nodes log theirs:
//
//	audit: action=control_cli by="alice (cli)" from=local target="ento control allow servers servers" result=ok
//
// "by" is whoever ran it (the user behind sudo). The arguments name no secret (tokens are printed,
// never taken as arguments).
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
}
