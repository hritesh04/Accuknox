package bpflsm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang lsm ../../BPF/drop_packets_lsm.c -- -I/usr/include -O2 -g

type LSMEnforcer struct {
	obj  lsmObjects
	link link.Link
}

func (be *LSMEnforcer) Showlogs() {
	buffer, err := ringbuf.NewReader(be.obj.Buffer)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer buffer.Close()

	var event eventType
	for {
		record, err := buffer.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		log.Printf("Connection Type : %s\tStatus : %s", getConnectionType(event.Type), getActionType(event.Action))
	}
}

func NewLSMEnforcer(port []byte) (*LSMEnforcer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	be := new(LSMEnforcer)

	if err := loadLsmObjects(&be.obj, &ebpf.CollectionOptions{}); err != nil {
		return nil, err
	}

	key := uint64(0)
	keybuf := new(bytes.Buffer)
	if err := binary.Write(keybuf, binary.LittleEndian, key); err != nil {
		return nil, err
	}

	if err := be.obj.PortData.Put(keybuf.Bytes(), port); err != nil {
		return nil, err
	}

	var err error
	be.link, err = link.AttachLSM(link.LSMOptions{Program: be.obj.LsmTcpDrop})
	if err != nil {
		return nil, err
	}
	log.Println("eBPF program loaded and attached.")

	return be, nil
}

func (be *LSMEnforcer) Stop() error {
	err := be.link.Close()
	if err != nil {
		log.Fatalf("error detaching XDP program: %v", err)
		return err
	}
	log.Println("XDP program detached.")
	return nil
}
