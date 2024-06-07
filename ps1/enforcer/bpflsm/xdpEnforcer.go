package bpflsm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang xdp ../../BPF/drop_packets_xdp.c -- -I/usr/include -O2 -g

type XDPEnforcer struct {
	obj  xdpObjects
	link link.Link
}

func (be *XDPEnforcer) Showlogs() {
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

func NewXDPEnforcer(port []byte) (*XDPEnforcer, error) {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	be := new(XDPEnforcer)

	if err := loadXdpObjects(&be.obj, &ebpf.CollectionOptions{}); err != nil {
		log.Fatalf("error loading BPF XDP objects: %v", err)
		return nil, err
	}

	key := uint64(0)
	keybuf := new(bytes.Buffer)
	if err := binary.Write(keybuf, binary.LittleEndian, key); err != nil {
		log.Fatal("buffer error")
	}

	if err := be.obj.PortData.Put(keybuf.Bytes(), port); err != nil {
		log.Fatalf("updating map: %v", err)
	}

	// local network interface lo
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		log.Fatalf("lookup network interface: %v", err)
	}

	be.link, err = link.AttachXDP(link.XDPOptions{Program: be.obj.XdpDropTcpPorts, Interface: iface.Index})
	if err != nil {
		log.Fatalf("opening xdp %s: %s", be.obj.XdpDropTcpPorts.String(), err)
		return nil, err
	}
	log.Println("eBPF program loaded and attached.")

	return be, nil
}

func (be *XDPEnforcer) Stop() error {
	err := be.link.Close()
	if err != nil {
		log.Fatalf("error detaching XDP program: %v", err)
		return err
	}
	log.Println("XDP program detached.")
	return nil
}
