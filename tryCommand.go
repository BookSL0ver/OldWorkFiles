package main

import (
	"os/exec"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func main() {
	cmd := exec.Command("ip","-4","addr","show")
	list, err := cmd.Output()
	if err != nil {
		fmt.Println("ERROR")
	} else {
		for _, value := range list {
			fmt.Print(string(value))
		}
	}
	fmt.Println("\n")
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for index, addr := range addrs {
			addr_list := strings.Split(addr.String(), "/")
			fmt.Println(iface.Name + " " + strconv.Itoa(index) + ": " + addr_list[0])
		}
	}
}
