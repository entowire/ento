package agent

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type fakeSessionOps struct {
	result  LoginResult
	waitErr error
	block   bool // wait until the sign-in is ended
	logouts int
}

func (f *fakeSessionOps) status() SessionReply {
	return SessionReply{Event: "status", User: "anna", SessionActive: true, Version: "test"}
}

func (f *fakeSessionOps) startLogin(context.Context, bool) (string, string, func(context.Context) (LoginResult, error), error) {
	return "https://id.example.com/device?code=ABCD", "ABCD", func(ctx context.Context) (LoginResult, error) {
		if f.block {
			<-ctx.Done()
			return LoginResult{}, ctx.Err()
		}
		return f.result, f.waitErr
	}, nil
}

func (f *fakeSessionOps) logout(context.Context) (bool, error) {
	f.logouts++
	return true, nil
}

// exchange runs one request through a session server and returns the replies the client got.
func exchange(t *testing.T, s *sessionServer, ctx context.Context, op string) ([]SessionReply, error) {
	return exchangeAs(t, s, ctx, op, true)
}

func exchangeAs(t *testing.T, s *sessionServer, ctx context.Context, op string, mayAct bool) ([]SessionReply, error) {
	t.Helper()
	client, server := net.Pipe()
	go s.serve(context.Background(), server, `PC\anna (process 1, session 1)`, mayAct)
	var got []SessionReply
	err := sessionExchange(ctx, client, SessionRequest{Op: op}, func(r SessionReply) error {
		got = append(got, r)
		return nil
	})
	return got, err
}

func TestSessionChannel(t *testing.T) {
	ops := &fakeSessionOps{result: LoginResult{User: "anna", Approved: true}}
	var logged []string
	s := &sessionServer{ops: ops, logf: func(f string, a ...any) { logged = append(logged, f) }}
	ctx := context.Background()

	got, err := exchange(t, s, ctx, "status")
	if err != nil || len(got) != 1 || got[0].User != "anna" || !got[0].SessionActive {
		t.Fatalf("status: %+v, %v", got, err)
	}

	got, err = exchange(t, s, ctx, "login")
	if err != nil || len(got) != 2 || got[0].Event != "link" || got[0].Code != "ABCD" ||
		got[1].Event != "done" || got[1].User != "anna" || !got[1].Approved {
		t.Fatalf("login: %+v, %v", got, err)
	}

	got, err = exchange(t, s, ctx, "logout")
	if err != nil || len(got) != 1 || !got[0].Delivered || ops.logouts != 1 {
		t.Fatalf("logout: %+v, %v (%d)", got, err, ops.logouts)
	}

	if _, err := exchange(t, s, ctx, "rm -rf"); err == nil || !strings.Contains(err.Error(), "unknown request") {
		t.Fatalf("unknown op: %v", err)
	}

	// A remote desktop's program may ask, not act.
	if got, err := exchangeAs(t, s, ctx, "status", false); err != nil || len(got) != 1 {
		t.Fatalf("remote status: %+v, %v", got, err)
	}
	for _, op := range []string{"login", "logout"} {
		if _, err := exchangeAs(t, s, ctx, op, false); err == nil || !strings.Contains(err.Error(), "screen") {
			t.Fatalf("remote %s: %v", op, err)
		}
	}
	if ops.logouts != 1 {
		t.Fatalf("a remote logout reached the agent")
	}

	ops.waitErr = errors.New("login expired")
	if got, err := exchange(t, s, ctx, "login"); err == nil || len(got) != 1 {
		t.Fatalf("expired login: %+v, %v", got, err)
	}
	if len(logged) == 0 {
		t.Fatal("nothing logged")
	}
}

// A second sign-in ends the one before, and a client that goes away ends its own.
func TestSessionLoginReplaced(t *testing.T) {
	ops := &fakeSessionOps{block: true}
	s := &sessionServer{ops: ops, logf: func(string, ...any) {}}
	first := make(chan error, 1)
	linked := make(chan struct{})
	go func() {
		client, server := net.Pipe()
		go s.serve(context.Background(), server, "first", true)
		first <- sessionExchange(context.Background(), client, SessionRequest{Op: "login"}, func(r SessionReply) error {
			if r.Event == "link" {
				close(linked)
			}
			return nil
		})
	}()
	<-linked
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	got, err := exchange(t, s, ctx, "login")
	if len(got) != 1 || got[0].Event != "link" || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second login: %+v, %v", got, err)
	}
	select {
	case err := <-first:
		if err == nil || !strings.Contains(err.Error(), "ended") {
			t.Fatalf("first login: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the first sign-in was not ended")
	}
}
