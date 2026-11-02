package main

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

// `ento` without arguments stays short, and names only commands the full help documents.
func TestShortUsage(t *testing.T) {
	if n := strings.Count(shortUsage, "\n"); n > 20 {
		t.Errorf("short usage has %d lines, keep it at 20 or fewer", n)
	}
	cmd := regexp.MustCompile(`ento (agent|admin|update) [a-z]+`)
	for _, c := range cmd.FindAllString(shortUsage, -1) {
		if !strings.Contains(usage, c) {
			t.Errorf("short usage names %q, which the full help does not document", c)
		}
	}
}

func TestHelpTopics(t *testing.T) {
	for topic, text := range helpTopics {
		var b bytes.Buffer
		if err := printHelp(&b, []string{topic}); err != nil {
			t.Fatalf("help %s: %v", topic, err)
		}
		if !strings.Contains(b.String(), strings.TrimRight(text, "\n")) || !strings.Contains(usage, text) {
			t.Errorf("help %s does not print its part of the full help", topic)
		}
	}
	var b bytes.Buffer
	if err := printHelp(&b, nil); err != nil || b.String() != usage {
		t.Errorf("help without a topic must print everything")
	}
	if err := printHelp(&b, []string{"nope"}); err == nil {
		t.Errorf("help for an unknown topic must fail")
	}
	for _, args := range [][]string{nil, {"help"}, {"-h"}, {"--help"}} {
		if !isHelp(args) {
			t.Errorf("isHelp(%q) = false", args)
		}
	}
	if isHelp([]string{"status"}) || isHelp([]string{"--help", "x"}) {
		t.Errorf("isHelp takes a command for help")
	}
}
