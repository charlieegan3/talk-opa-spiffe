.PHONY: demo
demo:
	find cmd/demo | entr -c -r go run ./cmd/demo/demo.go

.PHONY: bookings
bookings:
	find cmd/bookings | entr -c -r go run ./cmd/bookings/bookings.go

.PHONY: reservations
reservations:
	find cmd/reservations | entr -c -r go run ./cmd/reservations/reservations.go

.PHONY: station
station:
	./demo/station1_opa.sh

.PHONY: hq
hq:
	./demo/hq_opa.sh

.PHONY: browser
browser:
	open http://localhost:8080/config
	open http://localhost:8081
