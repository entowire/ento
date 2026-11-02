package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"rsc.io/qr"
)

// The terminal drawing, read back module by module, is the encoder's code plus the white margin.
func TestWriteQR(t *testing.T) {
	code, err := qr.Encode("ENTO1:EXAMPLE.COM:8A4D-0034-38BF-6588:ABACUS ZOOM GUMDROP DROPBOX SNOWDROP", qr.M)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	writeQR(&b, code.Size, code.Black)
	cell := regexp.MustCompile(`\x1b\[(\d+);(\d+)m▀`)
	var rows [][]bool
	for _, line := range strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n") {
		var top, bottom []bool
		for _, m := range cell.FindAllStringSubmatch(line, -1) {
			top, bottom = append(top, m[1] == "30"), append(bottom, m[2] == "40")
		}
		rows = append(rows, top, bottom)
	}
	n := code.Size + 8
	if len(rows) < n || len(rows[0]) != n {
		t.Fatalf("drawing is %dx%d modules, want %dx%d", len(rows[0]), len(rows), n, n)
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			want := x >= 4 && y >= 4 && x < code.Size+4 && y < code.Size+4 && code.Black(x-4, y-4)
			if rows[y][x] != want {
				t.Fatalf("module (%d,%d) = %v, want %v", x, y, rows[y][x], want)
			}
		}
	}
}

// A QR code carries the words: never into a file or a pipe.
func TestPrintQRRefusesNonTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := printQR(f, "ENTO1:X"); err == nil {
		t.Fatal("printQR wrote to a regular file")
	}
}
