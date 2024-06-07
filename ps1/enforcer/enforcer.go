package enforcer

import (
	"errors"
	"log"

	"github.com/hritesh04/accuknox/ps1/enforcer/bpflsm"
)

type BPFEnforcer interface {
	Showlogs()
	Stop() error
}

func NewEnforcer(port []byte, prog string) (BPFEnforcer, error) {
	var enforcer BPFEnforcer
	var err error
	switch prog {
	case "xdp":
		enforcer, err = bpflsm.NewXDPEnforcer(port)
		if err != nil {
			log.Fatal("Error create XDP enforcer")
			return nil, err
		}
		return enforcer, nil
	case "lsm":
		enforcer, err = bpflsm.NewLSMEnforcer(port)
		if err != nil {
			log.Fatalf("Error create LSM enforcer %s", err)
			return nil, err
		}
		return enforcer, nil
	default:
		log.Fatalf("Invalid prgram name %s ", prog)
		return nil, errors.ErrUnsupported
	}
}
