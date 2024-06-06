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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang enforcer ../../BPF/drop_packets_xdp.c -- -I/usr/include -O2 -g

type BPFEnforcer struct {
	obj    enforcerObjects
	probes map[string]link.Link
}

type eventType struct {
	Type   uint8
	Action uint8
}

func (be *BPFEnforcer) Showlogs() {
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

func NewBPFEnforcer(port []byte) (*BPFEnforcer, error) {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	be := new(BPFEnforcer)
	be.probes = make(map[string]link.Link)

	if err := loadEnforcerObjects(&be.obj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "sys/fs/bpf",
		},
	}); err != nil {
		log.Fatalf("error loading BPF LSM objects: %v", err)
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

	be.probes[be.obj.XdpDropTcpPorts.String()], err = link.AttachXDP(link.XDPOptions{Program: be.obj.XdpDropTcpPorts, Interface: iface.Index})
	if err != nil {
		log.Fatalf("opening lsm %s: %s", be.obj.XdpDropTcpPorts.String(), err)
		return nil, err
	}
	log.Println("eBPF program loaded and attached.")

	return be, nil
}

func getConnectionType(c uint8) string {
	switch c {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	default:
		return "UNKNOWN"
	}
}

func getActionType(a uint8) string {
	switch a {
	case 1:
		return "PASS"
	case 2:
		return "DROP"
	default:
		return "INVALID"
	}
}
