package api

import (
	"testing"
	"time"
)

func TestHumanDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0:                               "0s",
		45 * time.Second:                "45s",
		90 * time.Second:                "1m",
		30 * time.Minute:                "30m",
		time.Hour:                       "1h",
		135 * time.Minute:               "2h15m",
		24 * time.Hour:                  "1d",
		30 * time.Hour:                  "1d6h",
		720 * time.Hour:                 "30d",
		-15 * time.Minute:               "15m",
		15*time.Minute + 59*time.Second: "15m",
	} {
		if got := HumanDuration(d); got != want {
			t.Errorf("HumanDuration(%s) = %q, want %q", d, got, want)
		}
	}
}
