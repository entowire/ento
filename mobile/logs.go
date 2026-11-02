//go:build linux

package mobile

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// Logs (0.30.3). What the agent and the app log goes to Android's log, which only a computer with
// adb reads, and to a file in the app's own storage, so that a person whose app misbehaved can send
// it (the app's Send logs): logs/ento.log, rotated at 1 MiB (one older file kept). A Go panic,
// which ends the whole app, writes its report to logs/crash-go.txt. Nothing leaves the phone unless
// the person shares it. Lines never carry words, tokens or keys (the agent logs none).

const (
	logMax   = 1 << 20
	crashMax = 256 << 10
	shareMax = 768 << 10 // what Logs returns at most, newest first
)

var logFile struct {
	sync.Mutex
	dir  string
	f    *os.File
	size int64
}

// StartLogs opens the log file in dir (the app's logs folder) and sends Go panic reports to
// crash-go.txt there. The app calls it first, once per process.
func StartLogs(dir string) (err error) {
	defer plain(&err)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	logFile.Lock()
	if logFile.f != nil {
		logFile.Unlock()
		return nil
	}
	logFile.dir = dir
	err = openLog()
	logFile.Unlock()
	if err != nil {
		return err
	}
	crash := filepath.Join(dir, "crash-go.txt")
	if fi, err := os.Stat(crash); err == nil && fi.Size() > crashMax {
		_ = os.Truncate(crash, 0)
	}
	if f, err := os.OpenFile(crash, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		fmt.Fprintf(f, "\n--- process started %s (agent %s); a Go panic below this line ended it ---\n",
			time.Now().UTC().Format(time.RFC3339), version)
		_ = debug.SetCrashOutput(f, debug.CrashOptions{})
		f.Close() // SetCrashOutput keeps its own descriptor
	}
	writeLog("app", "started, agent "+version)
	return nil
}

// openLog opens (or rotates and opens) the log file; the caller holds logFile.
func openLog() error {
	path := filepath.Join(logFile.dir, "ento.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() >= logMax {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, _ := f.Stat()
	logFile.f, logFile.size = f, 0
	if fi != nil {
		logFile.size = fi.Size()
	}
	return nil
}

func writeLog(source, line string) {
	logFile.Lock()
	defer logFile.Unlock()
	if logFile.f == nil {
		return
	}
	s := time.Now().UTC().Format("2006-01-02T15:04:05.000Z") + " " + source + ": " + strings.TrimRight(line, "\n") + "\n"
	n, _ := io.WriteString(logFile.f, s)
	logFile.size += int64(n)
	if logFile.size >= logMax {
		logFile.f.Close()
		logFile.f = nil
		_ = openLog()
	}
}

// AppLog writes one line of the app's own (Java) to the log file.
func AppLog(line string) { writeLog("app", line) }

// agentLogf is the agent's log: Android's log and the file.
func agentLogf(f string, a ...any) {
	msg := fmt.Sprintf(f, a...)
	log.Print("ento: " + msg)
	writeLog("agent", msg)
}

// Logs returns what Send logs shares: the crash reports, then the log, newest last, at most
// shareMax bytes in all (the oldest lines dropped first).
func Logs() string {
	logFile.Lock()
	dir := logFile.dir
	logFile.Unlock()
	if dir == "" {
		return "no logs (not started)\n"
	}
	var b strings.Builder
	for _, name := range []string{"crash-go.txt", "crash-java.txt", "exits.txt"} {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil && len(strings.TrimSpace(string(data))) > 0 {
			fmt.Fprintf(&b, "===== %s =====\n%s\n", name, tail(data, 128<<10))
		}
	}
	var lines []byte
	for _, name := range []string{"ento.log.1", "ento.log"} {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			lines = append(lines, data...)
		}
	}
	room := shareMax - b.Len()
	if room < 64<<10 {
		room = 64 << 10
	}
	fmt.Fprintf(&b, "===== ento.log =====\n%s", tail(lines, room))
	return b.String()
}

// tail keeps the last n bytes of data, from a line's start.
func tail(data []byte, n int) string {
	if len(data) <= n {
		return string(data)
	}
	data = data[len(data)-n:]
	if i := strings.IndexByte(string(data), '\n'); i >= 0 {
		data = data[i+1:]
	}
	return "(older lines left out)\n" + string(data)
}
