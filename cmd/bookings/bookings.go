package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"html/template"
	"io"
	"net/http"

	"github.com/charlieegan3/talk-opa-spiffe/internal/pkg/sources"
	"github.com/charlieegan3/talk-opa-spiffe/internal/types"
)

//go:embed templates/*
var templates embed.FS

var drivers = map[string]types.Driver{
	"d0001": {ID: "d0001"},
	"d0002": {ID: "d0002"},
	"d0003": {ID: "d0003"},
}
var trains = map[string]types.Train{
	"t0001": {ID: "t0001"},
	"t0002": {ID: "t0002"},
	"t0003": {ID: "t0003"},
}

var trainServices = map[string]types.TrainService{
	"ts0001": {
		ID:       "ts0001",
		DriverID: "d0001",
		TrainID:  "t0001",
	},
	"ts0002": {
		ID:       "ts0002",
		DriverID: "d0002",
		TrainID:  "t0002",
	},
	"ts0003": {
		ID:       "ts0003",
		DriverID: "d0003",
		TrainID:  "t0003",
	},
}

var reservations = map[string]types.Reservation{
	"r0001": {
		ID:             "r0001",
		TrainServiceID: "ts0001",
		BookingID:      "b0001",
		Seat:           "A1",
	},
	"r0002": {
		ID:             "r0002",
		TrainServiceID: "ts0001",
		BookingID:      "b0002",
		Seat:           "C2",
	},
	"r0003": {
		ID:             "r0003",
		TrainServiceID: "ts0002",
		BookingID:      "b0003",
		Seat:           "F9",
	},
	"r0004": {
		ID:             "r0004",
		TrainServiceID: "ts0002",
		BookingID:      "b0004",
		Seat:           "H39",
	},
	"r0005": {
		ID:             "r0005",
		TrainServiceID: "ts0003",
		BookingID:      "b0005",
		Seat:           "A13",
	},
	"r0006": {
		ID:             "r0006",
		TrainServiceID: "ts0003",
		BookingID:      "b0006",
		Seat:           "B11",
	},
}

var bookings = map[string]types.Booking{
	"b0001": {
		ID:    "b0001",
		Email: "anna@example.com",
	},
	"b0002": {
		ID:    "b0002",
		Email: "bob@example.com",
	},
	"b0003": {
		ID:    "b0003",
		Email: "charlotte@example.com",
	},
	"b0004": {
		ID:    "b0004",
		Email: "dan@example.com",
	},
	"b0005": {
		ID:    "b0005",
		Email: "elena@example.com",
	},
	"b0006": {
		ID:    "b0006",
		Email: "fred@example.com",
	},
}

func main() {
	svid, err := x509svid.Load("svid__clusters_hq_bookings_cert.pem", "svid__clusters_hq_bookings_key.pem")
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
	r.Handle("/", http.HandlerFunc(indexHandler))
	r.Handle("/api/reservations/", http.HandlerFunc(reservationsHandler))
	r.Handle("/api/reservations/{trainServiceID}", http.HandlerFunc(reservationsHandler))

	addr := "localhost:8082"
	server := &http.Server{
		Handler:   r,
		Addr:      addr,
		TLSConfig: tlsConfig,
	}

	fmt.Println("Listening on", addr)
	server.ListenAndServeTLS("", "")
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
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

func reservationsHandler(w http.ResponseWriter, r *http.Request) {
	trainServiceID := mux.Vars(r)["trainServiceID"]

	trainService, trainServiceFound := trainServices[trainServiceID]

	driver := r.Header.Get("X-DRIVER-ID")
	callerSpiffeID := r.TLS.PeerCertificates[0].URIs[0].String()

	// configure SPIFFE tls to OPA
	svid, err := x509svid.Load("svid__clusters_hq_bookings_cert.pem", "svid__clusters_hq_bookings_key.pem")
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

	serverID := spiffeid.RequireFromString("spiffe://example.com/clusters/hq/opa")
	tlsConfig := tlsconfig.MTLSClientConfig(source, b, tlsconfig.AuthorizeID(serverID))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	body := map[string]interface{}{
		"caller":         callerSpiffeID,
		"driver":         driver,
		"train_service":  trainServiceID,
		"reservations":   reservations,
		"train_services": trainServices,
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequest("POST", "https://localhost:8182/v0/data/reservations/list/deny", bytes.NewReader(bodyJSON))
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

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(string(respBody))
		w.Write(respBody)
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
		w.WriteHeader(http.StatusForbidden)
		w.Write(respBody)
		return
	}

	// check with OPA if we can show the emails
	req, err = http.NewRequest("POST", "https://localhost:8182/v0/data/reservations/list/option", bytes.NewReader(bodyJSON))
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp, err = client.Do(req)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	respBody, err = io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Println(string(respBody))
		w.Write(respBody)
		return
	}

	var opaResponseOptions map[string]bool

	err = json.Unmarshal(respBody, &opaResponseOptions)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var selectedReservations []types.Reservation
	for _, reservation := range reservations {
		if trainServiceFound {
			if reservation.TrainServiceID == trainService.ID {
				selectedReservations = append(selectedReservations, types.Reservation{
					ID:             reservation.ID,
					TrainServiceID: reservation.TrainServiceID,
					BookingID:      reservation.BookingID,
					Seat:           reservation.Seat,
					Booking:        bookings[reservation.BookingID],
					TrainService:   trainServices[reservation.TrainServiceID],
				})
			}
		} else {
			selectedReservations = append(selectedReservations, types.Reservation{
				ID:             reservation.ID,
				TrainServiceID: reservation.TrainServiceID,
				BookingID:      reservation.BookingID,
				Seat:           reservation.Seat,
				Booking:        bookings[reservation.BookingID],
				TrainService:   trainServices[reservation.TrainServiceID],
			})
		}
	}

	for i, _ := range selectedReservations {
		if val, ok := opaResponseOptions["show_email"]; ok && !val {
			selectedReservations[i].Booking.Email = "REDACTED by OPA"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	bytes, err := json.Marshal(selectedReservations)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = w.Write(bytes)
}
