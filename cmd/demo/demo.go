package main

import (
	"bytes"
	"crypto/md5"
	"embed"
	"fmt"
	"github.com/alecthomas/chroma/quick"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/charlieegan3/talk-opa-spiffe/internal/pkg/sources"
)

//go:embed templates/*
var templates embed.FS

var policyData = map[string]string{
	"station1/system.authz": `
package system.authz

default allow := {
	"allowed": false,
	"reason": "Station OPA only accepts authenticated clients"	
}
`,
	"station1/reservations.list": `
package reservations.list

deny[reason] {
	false
	reason := "TODO"
}
`,
	"hq/system.authz": `
package system.authz

default allow := {
	"allowed": false,
	"reason": "HQ OPA only accepts authenticated clients"	
}
`,
	"hq/reservations.list": `
package reservations.list

deny[reason] {
	false
	reason := "TODO"
}

option["TODO"] := true
`,
}

var policyNotes = map[string]string{
	"station1/system.authz": `
package system.authz

spiffeIDString(spiffeID) = result {
	result := sprintf("spiffe://%s%s", [spiffeID.Host, spiffeID.Path])
}

default allow := {
	"allowed": false,
	"reason": "Station OPA only accepts authenticated clients"
}

allow := { "allowed": true } {
	spiffeIDString(input.client_certificates[0].URIs[0])
}

###########################################################

package system.authz

import future.keywords.in

spiffeIDString(spiffeID) = result {
	result := sprintf("spiffe://%s%s", [spiffeID.Host, spiffeID.Path])
}

default allow := {
	"allowed": false,
	"reason": "Station OPA only accepts authenticated clients"
}

acl := {
	"spiffe://example.com/clusters/station1/reservations": [
		["v0", "data", "reservations", "list", "deny"],
	],
}

allow := { "allowed": false, "reason": reason } {
	spiffeID := spiffeIDString(input.client_certificates[0].URIs[0])
	not acl[spiffeID]
	reason := sprintf("client %s is not authorized to access this OPA", [spiffeID])
}

allow := { "allowed": false, "reason": reason } {
	spiffeID := spiffeIDString(input.client_certificates[0].URIs[0])
	not input.path in acl[spiffeID]
	reason := sprintf("client %s is not authorized to access this path %s", [spiffeID, input.path])
}

allow := { "allowed": true } {
	spiffeID := spiffeIDString(input.client_certificates[0].URIs[0])
	input.path in acl[spiffeID]
}
`,
	"station1/reservations.list": `
package reservations.list

deny[reason] {
	input.driver == ""
	reason := "driver must be not be a empty"
}
deny[reason] {
	input.train == ""
	reason := "train must be not be a empty"
}
`,
	"hq/reservations.list": `
package reservations.list

deny[reason] {
	input.driver == ""
	reason := "driver must be not be a empty"
}

deny[reason] {
	input.train_service == ""
	reason := "train must be not be a empty"
}

deny[reason] {
	input.train_services[input.train_service].DriverID != input.driver
	reason := "Driver does not match requested train service"
}

###########################################################

option["show_email"] := false {
  input.caller == "spiffe://example.com/clusters/station1/reservations"
}
`,
	"hq/system.authz": `
package system.authz

import future.keywords.in

spiffeIDString(spiffeID) = result {
	result := sprintf("spiffe://%s%s", [spiffeID.Host, spiffeID.Path])
}

default allow := {
	"allowed": false,
	"reason": "HQ OPA only accepts authenticated clients"
}

acl := {
	"spiffe://example.com/clusters/hq/bookings": [
		["v0", "data", "reservations", "list", "deny"],
	],
}

allow := { "allowed": false, "reason": reason } {
	spiffeID := spiffeIDString(input.client_certificates[0].URIs[0])
	not input.path in acl[spiffeID]
	reason := sprintf("client %s is not authorized to access this path %s", [spiffeID, input.path])
}

allow := { "allowed": true } {
	spiffeID := spiffeIDString(input.client_certificates[0].URIs[0])
	input.path in acl[spiffeID]
}
`,
}

func main() {
	svid, err := x509svid.Load("svid__demo_cert.pem", "svid__demo_key.pem")
	if err != nil {
		panic(err)
	}
	if svid == nil {
		panic(err)
	}

	td, err := spiffeid.TrustDomainFromString("example.com")
	if err != nil {
		panic(err)
	}

	b, err := x509bundle.Load(td, "ca.pem")
	if err != nil {
		panic(err)
	}

	source := &sources.Basic{SVID: svid}

	tlsConfig := tlsconfig.MTLSServerConfig(source, b, tlsconfig.AuthorizeMemberOf(td))

	r := mux.NewRouter()
	r.Handle("/config", http.HandlerFunc(configIndexHandler))
	r.Handle("/config/{site}/{bundle}", http.HandlerFunc(configShowHandler))
	r.Handle("/bundles/{site}/{bundle}/bundle.tar.gz", http.HandlerFunc(bundleHandler))

	addr := "localhost:8080"
	server := &http.Server{
		Handler:   r,
		Addr:      addr,
		TLSConfig: tlsConfig,
	}

	fmt.Println("Listening on", addr)
	// TODO TLS
	//server.ListenAndServeTLS("", "")
	server.ListenAndServe()
}

func bundleHandler(w http.ResponseWriter, r *http.Request) {
	var err error

	site := mux.Vars(r)["site"]
	bundleID := mux.Vars(r)["bundle"]

	if site == "" || bundleID == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	key := fmt.Sprintf("%s/%s", site, bundleID)

	h := md5.New()
	io.WriteString(h, policyData[key])
	hash := fmt.Sprintf("%x", h.Sum(nil))

	if r.Header.Get("If-None-Match") == hash {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	fmt.Println(r.URL.Path, "new bundle", hash)

	roots := []string{strings.Replace(bundleID, ".", "/", -1)}
	b := bundle.Bundle{
		Manifest: bundle.Manifest{
			Roots: &roots,
		},
		Modules: []bundle.ModuleFile{
			{
				URL: "policy.rego",
				Raw: []byte(policyData[key]),
			},
		},
	}

	w.Header().Set("content-type", "application/vnd.openpolicyagent.bundles")
	w.Header().Set("etag", hash)
	err = bundle.NewWriter(w).Write(b)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func configIndexHandler(w http.ResponseWriter, r *http.Request) {
	bs, err := templates.ReadFile("templates/index.html")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	t := template.New("page")
	ct, err := t.Parse(string(bs))
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = ct.Execute(w, nil)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func configShowHandler(w http.ResponseWriter, r *http.Request) {
	site := mux.Vars(r)["site"]
	bundleID := mux.Vars(r)["bundle"]

	key := fmt.Sprintf("%s/%s", site, bundleID)

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		value := r.Form.Get("value")
		policyData[key] = value
	}

	bs, err := templates.ReadFile("templates/config.html")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	t := template.New("page")
	ct, err := t.Parse(string(bs))
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	current, _ := policyData[key]
	notes := policyNotes[key]

	var currentFormatted bytes.Buffer
	err = quick.Highlight(&currentFormatted, current, "ruby", "html", "monokailight")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var notesFormatted bytes.Buffer
	err = quick.Highlight(&notesFormatted, notes, "ruby", "html", "monokailight")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = ct.Execute(w, struct {
		Key         string
		Current     string
		Notes       string
		CurrentHTML template.HTML
		NotesHTML   template.HTML
	}{
		Key:         key,
		Current:     current,
		Notes:       notes,
		CurrentHTML: template.HTML(currentFormatted.String()),
		NotesHTML:   template.HTML(notesFormatted.String()),
	})
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
