package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/charlieegan3/talk-opa-spiffe/internal/types"
	"github.com/gorilla/mux"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/charlieegan3/talk-opa-spiffe/internal/pkg/sources"
)

//go:embed templates/*
var templates embed.FS

func main() {
	svid, err := x509svid.Load("svid__clusters_station1_reservations_cert.pem", "svid__clusters_station1_reservations_key.pem")
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
	r.HandleFunc("/", indexHandler)
	r.HandleFunc("/reservations", reservationsHandler)

	server := &http.Server{
		Handler:   r,
		Addr:      ":8081",
		TLSConfig: tlsConfig,
	}

	// TODO TLS
	//server.ListenAndServeTLS("", "")
	server.ListenAndServe()
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	bs, err := templates.ReadFile("templates/index.html")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	t := template.New("page")
	ct, err := t.Parse(string(bs))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	err = ct.Execute(w, nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func reservationsHandler(w http.ResponseWriter, r *http.Request) {
	driver := r.URL.Query().Get("driver")
	train := r.URL.Query().Get("train")

	svid, err := x509svid.Load("svid__clusters_station1_reservations_cert.pem", "svid__clusters_station1_reservations_key.pem")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if svid == nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	td, err := spiffeid.TrustDomainFromString("example.com")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	bundle, err := x509bundle.Load(td, "ca.pem")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	source := &sources.Basic{SVID: svid}

	serverID := spiffeid.RequireFromString("spiffe://example.com/clusters/station1/opa")
	tlsConfig := tlsconfig.MTLSClientConfig(source, bundle, tlsconfig.AuthorizeID(serverID))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	body := map[string]string{
		"driver": driver,
		"train":  train,
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequest("POST", "https://localhost:8181/v0/data/reservations/list/deny", bytes.NewReader(bodyJSON))
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		bs, err := templates.ReadFile("templates/reservations.error.html")
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		t := template.New("page")
		ct, err := t.Parse(string(bs))
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		err = ct.Execute(w, struct {
			Message string
		}{
			Message: string(respBody),
		})
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	var opaResponse []string

	err = json.Unmarshal(respBody, &opaResponse)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if len(opaResponse) > 0 {
		bs, err := templates.ReadFile("templates/reservations.error.html")
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
		}

		t := template.New("page")
		ct, err := t.Parse(string(bs))
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		err = ct.Execute(w, struct {
			Message string
		}{
			Message: strings.Join(opaResponse, ", "),
		})
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	reservations := []types.Reservation{
		{
			ID:             "1",
			TrainServiceID: "ts1",
			Seat:           "A1",
		},
	}

	bs, err := templates.ReadFile("templates/reservations.html")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	t := template.New("page")
	ct, err := t.Parse(string(bs))
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
	}

	err = ct.Execute(w, struct {
		Driver       string
		Train        string
		Reservations []types.Reservation
	}{
		Driver:       driver,
		Train:        train,
		Reservations: reservations,
	})
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
