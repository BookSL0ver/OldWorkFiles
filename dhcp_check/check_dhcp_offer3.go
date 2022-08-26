package main

import (
	"fmt"						//input/output
	"github.com/google/gopacket"			//seems to be how to get pcap to work
	"github.com/google/gopacket/pcap"
	//"github.com/google/gopacket/layers"
	"time"						//used for timeout
	//"log"						//used for errors
//	"net"
	"math/rand"					//makes the random transaction id possible
	"github.com/u-root/dhcp4/dhcp4client"
	"flag"
	"github.com/u-root/dhcp4/vendor/github.com/vishvananda/netlink"
)


var (
	device			string = "eth0"				//where it looks
	snapshot_len		int32  = 1024
	promiscuous		bool   = true				//allows it to see packets from other devices
	err			error					//will hold any errors
	timeout			time.Duration = 30 * time.Second	//length of time to look at packets
	handle			*pcap.Handle
	buffer			gopacket.SerializeBuffer
	options			gopacket.SerializeOptions
	send_transaction_id	uint32 = (rand.Uint32()*0xFFFFFFFF)	//random transaction id
)


func main() {
	iface := flag.String("iface", "", "interface")
	client_mac := flag.String("client-mac", "", "mac address")
	//these are optional, not sure how to make them optional... also whether or not they are strings or something else
	server_ip := flag.String("server-ip", "", "source ip")
	server_mac := flag.String("server-mac", "", "mac address of server")
	lease_time := flag.String("lease-time", "", "lease-time")
	help := flag.Bool("help", false, "print help")

	flag.Parse()

	if *help {
		fmt.Println("Help output here")
		return
	}

	//need to figure out how to make a netlink
	//la := netlink.NewLinkAttrs()
	//la.Name = "eth0"
	/*mybridge := &netlink.Bridge{LinkAttrs: la}
	err := netlink.LinkAdd(mybridge)
	if err != nil {
		fmt.Printf("could not add %s: %v\n", la.Name, err)
	}
	eth0, _ := netlink.LinkByName("eth0")
	netlink.LinkSetMaster(eth0, mybridge)*/
	newlink, err := netlink.LinkByName("eth0")

//	inface, err := net.InterfaceByName(*iface)	//this is wrong -> need to figure out netlinks
	client, err := dhcp4client.New(newlink, options)		//so I wonder if the things above could basically check if somehting is in them and add them to a list called options if there is
	client.DiscoverOffer()
}
