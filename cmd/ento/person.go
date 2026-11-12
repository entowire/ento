package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"entowire.com/ento/internal/agent"
)

// loginCommand is how the person signs in again on this system (Windows: no administrator needed
// since 0.35, through the agent's person's channel).
var loginCommand = map[bool]string{true: "ento login", false: "sudo ento login"}[runtime.GOOS == "windows"]

// personChannel reports whether this command should ask the running agent through the person's
// channel: the device's state is out of this user's reach (Windows: not an administrator's
// elevated PowerShell) and the agent answers there.
func personChannel(stateDir string) bool {
	if _, err := agent.LoadState(stateDir); !errors.Is(err, os.ErrPermission) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := agent.SessionStatus(ctx)
	return err == nil
}

// personStatus prints what the person's channel says (`ento status` without the device's
// state: the rest needs an administrator).
func personStatus(ctx context.Context) error {
	st, err := agent.SessionStatus(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("agent:      running (ento %s)\n", agent.Printable(st.Version))
	who := agent.Printable(st.User)
	if st.UserName != "" && st.UserName != st.User {
		who += " (" + agent.Printable(st.UserName) + ")"
	}
	switch {
	case st.User == "":
		fmt.Printf("user:       nobody is signed in on this device (%s)\n", loginCommand)
	case st.SessionActive:
		fmt.Printf("user:       %s\nsession:    open (ento logout ends it)\n", who)
	default:
		fmt.Printf("user:       %s\nsession:    closed: %s opens it again\n", who, loginCommand)
	}
	fmt.Println("(peers, posture and addresses: ento status in an administrator's PowerShell)")
	return nil
}
