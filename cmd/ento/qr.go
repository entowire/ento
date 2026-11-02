package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"rsc.io/qr"
)

// printQR draws text as a QR code on a terminal, two modules per character cell (upper half block,
// explicit black on white so it scans on dark terminals too), with the standard 4-module margin.
// It refuses when w is not a terminal: the code carries a secret and must not end up in a file or log.
func printQR(w *os.File, text string) error {
	if !isTerminal(w) {
		return errors.New("--qr draws on a terminal only")
	}
	enableTerminalColors(w)
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	writeQR(w, code.Size, code.Black)
	return nil
}

func isTerminal(w *os.File) bool {
	fi, err := w.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func writeQR(w io.Writer, size int, black func(x, y int) bool) {
	const margin = 4
	dark := func(x, y int) bool {
		x, y = x-margin, y-margin
		return x >= 0 && y >= 0 && x < size && y < size && black(x, y)
	}
	color := func(d bool, fg bool) int {
		switch {
		case d && fg:
			return 30
		case d:
			return 40
		case fg:
			return 97
		default:
			return 107
		}
	}
	n := size + 2*margin
	var b strings.Builder
	for y := 0; y < n; y += 2 {
		for x := 0; x < n; x++ {
			fmt.Fprintf(&b, "\x1b[%d;%dm▀", color(dark(x, y), true), color(dark(x, y+1), false))
		}
		b.WriteString("\x1b[0m\n")
	}
	io.WriteString(w, b.String())
}
