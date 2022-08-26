package main

import (
	"fmt"						//input/output
//	"github.com/google/gopacket"			//seems to be how to get pcap to work
//	"github.com/google/gopacket/pcap"
//	"github.com/google/gopacket/layers"
//	"time"
	"log"						//used for errors
	"net"
	"github.com/d2g/dhcp4client"
	"github.com/d2g/dhcp4"
	"flag"
	"syscall"
)


var (
	err			error					//will hold any errors
)


func main() {
	//flags
	iface := flag.String("interface", "", "interface")
	client_mac := flag.String("client-mac", "", "mac address of client")
	//these are optional
	server_ip := flag.String("server-ip", "", "server ip")
	h := flag.Bool("help", false, "help")

	flag.Parse()

	if *h {
		help()
		return
	}

	//translate flags into usable values
	byname, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Printf("Interface Error: %v\n", err)
	}

	m, err := net.ParseMAC(*client_mac)
	if err != nil {
		log.Printf("Mac Error:%v\n", err)
	}

	c, err := dhcp4client.NewPacketSock(byname.Index)
	if err != nil {
		log.Fatal("Client Connection Generation:" + err.Error())
	}
	defer c.Close()

	client, err := dhcp4client.New(dhcp4client.HardwareAddr(m), dhcp4client.Connection(c))
	if err != nil {
		log.Fatal("dhcp client creation error: %v\n", err)
	}
	defer client.Close()

	client.SetOption(dhcp4client.HardwareAddr(m), dhcp4client.Connection(c))		//GenerateXID(g func([]byte))??? wait no it seems like new calls this on it's own

	offerPacket := discoverOffer(client)
	parsePacket(offerPacket, server_ip, server_mac, lease_time)
}

func help() {
	fmt.Println("Compiled by jwindorff on mikuni on 9/8/19")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("\t./check_dhcp_offer --interface=INTERFACE --client-mac=CLIENT_MAC [OPTIONS]")
	fmt.Println()
	fmt.Println("--interface=INTERFACE")
	fmt.Println("\tThe interface to check. Can be a raw interface (eth0) or a vlan (vlan200)")
	fmt.Println()
	fmt.Println("--client-mac=MAC_ADDRESS")
	fmt.Println("\tThe mac address from which to send the packet")
	fmt.Println()
	fmt.Println("--server-ip=IP")
	fmt.Println("\tReturn critical unless hte source ip of the dhcp offer is IP")
	fmt.Println()
	fmt.Println("--help")
	fmt.Println("\tPrints this help text")
	return
}

func discoverOffer(client *dhcp4client.Client) dhcp4.Packet {
	discoveryPacket, err := client.SendDiscoverPacket()
	fmt.Println(discoveryPacket)

	if err != nil {
		sc, ok := err.(syscall.Errno)
		if ok {
			//Don't report a network down
			if sc != syscall.ENETDOWN {
				log.Fatal("Discovery Error:%v\n", err)
			}
		} else {
			log.Fatal("Discovery Error:%v\n", err)
		}
	}

	offerPacket, err := client.GetOffer(&discoveryPacket)
//	if !Equal(discoveryPacket.XId, offerPacket.XId) {				//does this make sense? b/c like the transaction ids in the two that I printed are different
//		fmt.Println("xids don't match")
//	}
	if err != nil {
		log.Fatal("Offer Error:%v\n", err)
	}

	return offerPacket
}

func parsePacket(packet dhcp4.Packet, server_ip, server_mac, lease_time *string) {
	success := false
	//TODO: need to check offerPacket is right, then mark it as successful
	fmt.Println(packet.OpCode())
	if packet.OpCode() != 2 {
		log.Printf("Wrong return packet type")
	}

	sip := net.ParseIP(*server_ip)
	if sip == nil {
		fmt.Println("nil")
	} else {
		fmt.Println(packet.SIAddr())
		fmt.Println(sip)
	}

	if *server_ip != "" {
		if !(packet.SIAddr().Equal(sip)) {
			log.Printf("Wrong server ip")
		}
	}

	if *server_mac != "" {
		//maybe don't need?
	}

	lt := []byte(*lease_time)
	fmt.Println(packet.Secs())
	fmt.Println(lt)
	if *lease_time != "" {
		if !Equal(packet.Secs(),lt) {
			log.Printf("Wrong lease time")
		}
	}

	if packet != nil {
		success = true
	}

	fmt.Println(packet)

	if err != nil {
		networkError, ok := err.(net.Error)
		if ok && networkError.Timeout() {
			log.Fatal("Test Skipping as it didn't find a DHCP Server")
		}
		log.Fatal("Error:%v\n")
	}

	if !success {
		log.Fatal("Didn't successfully get a DHCP Lease")
	} else {
		log.Printf("DHCP offer recieved")
	}

}

func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
