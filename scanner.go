package main

import (
	"fmt"
	"os"
	"bufio"
	"syscall"
	"golang.org/x/crypto/ssh/terminal"
	"strings"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Username: ")
	scanner.Scan()
	usr := scanner.Text()
	fmt.Print("Password: ")
	scanner.Scan()
	pswrd := scanner.Text()
	fmt.Println(usr, pswrd)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username: ")
	usr, _ = reader.ReadString('\n')
	fmt.Print("Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err == nil {
		fmt.Println(strings.TrimSpace(usr), strings.TrimSpace(string(bytePassword)))
	}
}
