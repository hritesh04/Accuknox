package main

import (
	"fmt"
)

func main() {
	cnp := make(chan func(), 10)

	for i := 0; i < 4; i++ {
		go func() {
			for f := range cnp {
				f()
			}
		}()
	}
	// this function here is not called because because as soon it is send to the channel
	// the main control flow reaches the last fmt.Println("Hello") and the program exits leaving
	// no time for the the goroutines to pick up the function from the channel and execute it.
	cnp <- func() {
		fmt.Println("HERE1")
	}

	// if we add a sleep function here then the goroutine gets enough time to take the function
	// from the channel and execute it
	// time.Sleep(1 * time.Second)

	fmt.Println("Hello")
}
