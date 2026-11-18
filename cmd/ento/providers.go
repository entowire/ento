package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"entowire.com/ento/internal/agent"
	"entowire.com/ento/internal/api"
)

// Outside providers people sign in through (0.59): ento admin providers [set NAME ... | remove NAME
// | unlink EMAIL NAME]. Full administration.

const providersUsage = `usage: ento admin providers                       list them, and the addresses to register with each
       ento admin providers set NAME --title TITLE --issuer URL --client-id ID [--domains D,D] [--keep-secret]
                                                  add or change one (the client secret is asked for, or read from stdin)
       ento admin providers remove NAME
       ento admin providers unlink EMAIL NAME     forget the account at NAME that signs EMAIL in`

func adminProvidersCmd(ctx context.Context, c *agent.AdminClient, rest []string) error {
	old := func(err error) error {
		if code := agent.HTTPStatus(err); code == 405 {
			return errors.New("the control plane has no outside providers (older than ento 0.59)")
		}
		return err
	}
	op, args := sub(rest)
	switch op {
	case "":
		if len(args) > 0 {
			return errors.New(providersUsage)
		}
		var l api.IDProviders
		if err := c.Do(ctx, "GET", api.PathProviders, nil, &l); err != nil {
			return old(err)
		}
		if len(l.Providers) == 0 {
			fmt.Println("no outside providers: people sign in with passkeys, passwords and apps (ento admin providers set NAME ... adds one)")
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTITLE\tISSUER\tCLIENT\tDOMAINS")
			for _, p := range l.Providers {
				d := strings.Join(p.Domains, ",")
				if d == "" {
					d = "any"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", p.Name, cell(p.Title), p.Issuer, cell(p.ClientID), d)
			}
			if err := w.Flush(); err != nil {
				return err
			}
			if !l.Allowed {
				fmt.Println("\nthe default sign-in policy leaves \"provider\" out: only people in groups whose policy allows it sign in through one (the dashboard's People, Sign-in)")
			}
		}
		fmt.Println("\nregister these with each provider's client as where it sends people back (redirect URIs):")
		for _, u := range l.RedirectURIs {
			fmt.Println("  " + u)
		}
		return nil

	case "set":
		if len(args) < 1 || strings.HasPrefix(args[0], "-") {
			return errors.New(providersUsage)
		}
		name := args[0]
		fs := flag.NewFlagSet("admin providers set", flag.ContinueOnError)
		title := fs.String("title", "", `shown on the sign-in page as "Continue with TITLE" (e.g. Google)`)
		issuer := fs.String("issuer", "", "the provider's issuer (https://accounts.google.com; Microsoft: https://login.microsoftonline.com/<tenant ID>/v2.0)")
		client := fs.String("client-id", "", "the client registered at the provider (a web application)")
		domains := fs.String("domains", "", "only addresses in these domains (comma-separated; Google Workspace: your domain)")
		keep := fs.Bool("keep-secret", false, "change a provider without giving its client secret again")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 {
			return errors.New(providersUsage)
		}
		req := api.SetIDProviderRequest{Title: *title, Issuer: *issuer, ClientID: *client, Domains: splitList(*domains)}
		if !*keep {
			s, err := readSecret("client secret of " + name)
			if err != nil {
				return err
			}
			req.ClientSecret = s
		}
		if err := c.Do(ctx, "PUT", api.PathProviders+"/"+url.PathEscape(name), req, nil); err != nil {
			return old(err)
		}
		fmt.Printf("provider %s set: the sign-in page offers \"Continue with %s\"\n", name, *title)
		fmt.Println("people sign in through it only if the network has them (their address; ento admin providers lists where to register)")
		return nil

	case "remove":
		if len(args) != 1 {
			return errors.New(providersUsage)
		}
		if err := c.Do(ctx, "DELETE", api.PathProviders+"/"+url.PathEscape(args[0]), nil, nil); err != nil {
			return old(err)
		}
		fmt.Printf("provider %s removed\n", args[0])
		return nil

	case "unlink":
		if len(args) != 2 {
			return errors.New(providersUsage)
		}
		var people api.PeopleList
		if err := c.Do(ctx, "GET", api.PathPeople, nil, &people); err != nil {
			return err
		}
		id := ""
		for _, p := range people.People {
			if strings.EqualFold(p.Email, args[0]) {
				id = p.ID
			}
		}
		if id == "" {
			return fmt.Errorf("no person %s", args[0])
		}
		if err := c.Do(ctx, "DELETE", api.PathPeople+"/"+url.PathEscape(id)+"/providers/"+url.PathEscape(args[1]), nil, nil); err != nil {
			return old(err)
		}
		fmt.Printf("%s's %s account unlinked: their next sign-in through it links the account their address names then\n", args[0], args[1])
		return nil
	}
	return errors.New(providersUsage)
}

// readSecret reads a secret: typed at a prompt that does not show it, or piped in (one line).
func readSecret(what string) (string, error) {
	var line string
	var err error
	if isTerminal(os.Stdin) {
		fmt.Fprintf(os.Stderr, "%s (not shown): ", what)
		restore := noEcho(os.Stdin)
		line, err = bufio.NewReader(os.Stdin).ReadString('\n')
		restore()
		fmt.Fprintln(os.Stderr)
	} else {
		line, err = bufio.NewReader(os.Stdin).ReadString('\n')
		if errors.Is(err, io.EOF) && line != "" {
			err = nil
		}
	}
	line = strings.TrimSpace(line)
	if err != nil || line == "" {
		return "", fmt.Errorf("no %s given", what)
	}
	return line, nil
}
