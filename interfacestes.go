package main

import "net"
import "fmt"

func main() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error: ", err)
	}
	for _, iface := range ifaces {
		fmt.Println(iface)
	}

	byname, _ := net.InterfaceByName("eth0")
	fmt.Println(byname)

	fmt.Println(byname.Index)

	a := net.ParseIP("192.0.2.1")
	b := net.ParseIP("192.0.2.1")
	fmt.Println(a)
	fmt.Println(b)
	fmt.Println(a.Equal(b))
}
