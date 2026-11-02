//go:build !linux

package agent

import (
	"context"
	"net/http"
)

func manageLinks(context.Context, Config, *runner) {}

const linksSupported = false

// SetLinkProxy, CreateNamespace and DeleteNamespace exist for linked networks only (Linux).
func SetLinkProxy(string, string, string, string) error { return errNoLinks }
func CreateNamespace(string) error                      { return errNoLinks }
func DeleteNamespace(string) error                      { return errNoLinks }

// LinkHTTPClient exists for linked networks only (Linux).
func LinkHTTPClient(string) (*http.Client, func(), error) { return nil, nil, errNoLinks }
