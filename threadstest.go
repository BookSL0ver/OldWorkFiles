package main

import (
	"fmt"
)

func main() {
	messages := make(chan string)
	fmt.Println("before")
	go hi(messages)
	fmt.Println("between")
	wo(messages)
	msg := <-messages
	fmt.Println(msg)
	fmt.Println("after")
	fmt.Scanln()
	fmt.Println("done")
}

func hi(messages chan string) {
	fmt.Println("hi")
	msg := <-messages
	messages <- "2chan2"
	fmt.Println(msg)
}

func wo(messages chan string) {
	fmt.Println("wo")
	messages <- "chan"
}
