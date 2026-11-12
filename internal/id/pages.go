package id

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed pages
var pageFiles embed.FS

var pageTemplate = template.Must(template.ParseFS(pageFiles, "pages/page.html"))

// pageData is what a page shows; its script reads the mode and the rest from the body's data
// attributes (the pages run no inline script).
type pageData struct {
	Title   string
	Mode    string // authorize, device, here, setup, home or error
	Request string // authorize: the authorization request
	Client  string // authorize: the application's name
	Message string // error: what went wrong
	Device  string // here: the device the browser runs on
}

func (p *Provider) page(w http.ResponseWriter, status int, d pageData) {
	d.Title = p.cfg.Title
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pageTemplate.Execute(w, d); err != nil {
		p.cfg.Logf("identity provider: page: %v", err)
	}
}

func (p *Provider) homePage(w http.ResponseWriter, r *http.Request) {
	p.page(w, http.StatusOK, pageData{Mode: "home"})
}

func (p *Provider) devicePage(w http.ResponseWriter, r *http.Request) {
	p.page(w, http.StatusOK, pageData{Mode: "device"})
}

func (p *Provider) setupPage(w http.ResponseWriter, r *http.Request) {
	p.page(w, http.StatusOK, pageData{Mode: "setup"})
}

func (p *Provider) script(w http.ResponseWriter, r *http.Request) {
	serveFile(w, "pages/ento-id.js", "text/javascript; charset=utf-8")
}

func (p *Provider) style(w http.ResponseWriter, r *http.Request) {
	serveFile(w, "pages/ento-id.css", "text/css; charset=utf-8")
}

func serveFile(w http.ResponseWriter, name, contentType string) {
	b, err := pageFiles.ReadFile(name)
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(b)
}
