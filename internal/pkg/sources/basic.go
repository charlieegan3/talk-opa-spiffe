package sources

import "github.com/spiffe/go-spiffe/v2/svid/x509svid"

type Basic struct {
	SVID *x509svid.SVID
}

func (s *Basic) GetX509SVID() (*x509svid.SVID, error) {
	return s.SVID, nil
}
