package main

import (
	"fmt"
)

func main() {
	messages := make(chan string)
	//go func() {messages <- "ping" }()
	go t(messages)
	msg := <-messages
	fmt.Println(msg)
	done := make(chan bool, 1)
	go worker(done)
	<-done
	fmt.Println("done")
}

func t(messages chan string) {
	messages <- "ping"
}

func worker(done chan bool) {
	fmt.Println("worker")
	done <- true
}
