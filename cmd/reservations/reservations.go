package main

import (
	"errors"
	"fmt"
	"github.com/charlieegan3/talk-opa-spiffe/internal/pkg/sources"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"io"
	"net/http"
)

func main() {
	svid, err := x509svid.Load("svid_2_cert.pem", "svid_2_key.pem")
	if err != nil {
		panic(err)
	}
	if svid == nil {
		panic(errors.New("no SVID found"))
	}

	td, err := spiffeid.TrustDomainFromString("example.com")
	if err != nil {
		panic(err)
	}

	bundle, err := x509bundle.Load(td, "ca.pem")
	if err != nil {
		panic(err)
	}

	source := &sources.Basic{SVID: svid}

	serverID := spiffeid.RequireFromString("spiffe://example.com/prod/eu/cluster/services/server")
	tlsConfig := tlsconfig.MTLSClientConfig(source, bundle, tlsconfig.AuthorizeID(serverID))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	req, err := http.NewRequest("GET", "https://localhost:8181/v1/data", nil)
	if err != nil {
		panic(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	if err != nil {
		fmt.Println("Failure : ", err)
	}

	respBody, _ := io.ReadAll(resp.Body)

	// Display Results
	fmt.Println("response Status : ", resp.Status)
	fmt.Println("response Headers : ", resp.Header)
	fmt.Println("response Body : ", string(respBody))
}
