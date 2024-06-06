package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"strconv"

	_ "github.com/cilium/ebpf"
	"github.com/hritesh04/accuknox/ps1/enforcer/bpflsm"
)

func main() {

	portbuf := new(bytes.Buffer)
	if len(os.Args) < 2 {
		port := uint64(4040)
		log.Println("Port not specified")
		err := binary.Write(portbuf, binary.LittleEndian, port)
		if err != nil {
			log.Fatal("buffer error")
		}
		log.Println("Blocking the default port 4040")
	} else {
		port, err := strconv.ParseUint(os.Args[1], 10, 64)
		if err != nil {
			log.Fatalf("error pasrsing args %v", err)
		}
		if err := binary.Write(portbuf, binary.LittleEndian, port); err != nil {
			log.Fatal("buffer error")
		}
		log.Printf("Blocking port %s", os.Args[1])
	}
	enforcer, err := bpflsm.NewBPFEnforcer(portbuf.Bytes())
	if err != nil {
		log.Fatal("error creating enforcer")
	}
	enforcer.Showlogs()
}
