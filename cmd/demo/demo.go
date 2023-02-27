package main

import (
	"crypto/md5"
	"embed"
	"fmt"
	"html/template"
	"io"
	"log"
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

var data = map[string]string{
	"station1.system.authz": `
package system.authz

default allow := {
    "allowed": false,
    "reason": "this OPA only accepts SPIFFE clients"
}

# allow := { "allowed": true } {
#     spiffeID := input.client_certificates[0].URIs[0]
#     spiffeID.Scheme == "spiffe"
# }
`,
	"station1.reservations.list": `
package reservations.list

default deny := {
    "deny": false,
}

# deny := { "deny": true, "reason": reason } {
# 	not input.driver
# 	reason := "driver must be set"
# }
# 
# deny := { "deny": true, "reason": reason } {
# 	input.driver == ""
# 	reason := "driver must be not be an empty"
# }
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
	r.Handle("/config", http.HandlerFunc(configShowHandler))
	r.Handle("/bundles/{site}/{bundle}/bundle.tar.gz", http.HandlerFunc(bundleHandler))

	server := &http.Server{
		Handler:   r,
		Addr:      ":8080",
		TLSConfig: tlsConfig,
	}

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

	key := fmt.Sprintf("%s.%s", site, bundleID)

	h := md5.New()
	io.WriteString(h, data[key])
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
				Raw: []byte(data[key]),
			},
		},
	}

	w.Header().Set("content-type", "application/vnd.openpolicyagent.bundles")
	w.Header().Set("etag", hash)
	err = bundle.NewWriter(w).Write(b)
	if err != nil {
		log.Printf("error writing bundle: %v\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func configShowHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		key := r.Form.Get("key")
		value := r.Form.Get("value")

		if key != "" {
			data[key] = value
		}
	}

	bs, err := templates.ReadFile("templates/config.html")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	t := template.New("page")
	ct, err := t.Parse(string(bs))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	err = ct.Execute(w, struct {
		Data map[string]string
	}{Data: data})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}
