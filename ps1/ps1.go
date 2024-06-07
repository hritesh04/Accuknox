package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/hritesh04/accuknox/ps1/enforcer"
)

func main() {

	portbuf := new(bytes.Buffer)
	program := "xdp"
	switch len(os.Args) {
	case 3:
		port, err := strconv.ParseUint(os.Args[1], 10, 64)
		if err != nil {
			log.Fatalf("error pasrsing args %v", err)
		}
		if err := binary.Write(portbuf, binary.LittleEndian, port); err != nil {
			log.Fatal("buffer error")
		}
		program = strings.ToLower(os.Args[2])
		log.Printf("Blocking port %s using %s", os.Args[1], program)
	case 2:
		port, err := strconv.ParseUint(os.Args[1], 10, 64)
		if err != nil {
			log.Fatalf("error pasrsing args %v", err)
		}
		if err := binary.Write(portbuf, binary.LittleEndian, port); err != nil {
			log.Fatal("buffer error")
		}
		log.Printf("Program not specfied blocking port %s using xdp", os.Args[1])
		log.Printf("Blocking port %s", os.Args[1])
	default:
		port := uint64(4040)
		err := binary.Write(portbuf, binary.LittleEndian, port)
		if err != nil {
			log.Fatal("buffer error")
		}
		log.Printf("Program and Port not specfied blocking default port 4040 using xdp")
	}
	enforcerIntance, err := enforcer.NewEnforcer(portbuf.Bytes(), program)
	if err != nil {
		log.Fatal("error creating enforcer")
	}
	enforcerIntance.Showlogs()

}
