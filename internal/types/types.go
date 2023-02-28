package types

type TrainService struct {
	ID string

	DriverID string
	TrainID  string
}

type Driver struct {
	ID string
}

type Train struct {
	ID string
}

type Booking struct {
	ID string

	Email string
}

type Reservation struct {
	ID string

	TrainServiceID string
	BookingID      string

	Seat string

	// can be included in responses where needed
	Booking      Booking
	TrainService TrainService
}
