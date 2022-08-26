package main

import (
	"fmt"						//input/output
	"github.com/google/gopacket"			//seems to be how to get pcap to work
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"time"						//used for timeout
	"log"						//used for errors
	//"net"
	"math/rand"					//makes the random transaction id possible
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
	done := make(chan bool, 1)
	go reciever(done)
	//Do I need to wait for a sec here?
	sender()
	<-done
	errorchecking()
}


func reciever(done chan bool) {
	//code from https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket#intro 
	//Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil { log.Fatal(err) }
	defer handle.Close()
	fmt.Println("done")


	//Set filter
	var filter string = "dst port 68"	//not sure if this works... but that's how it was in perl
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("After filter")


	//Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("before packet reception")
	for packet := range packetSource.Packets() {
		//Process packet here
		dhcplayer := packet.Layer(layers.LayerTypeDHCPv4)
		if dhcplayer != nil {
			//recieved dhcp packet
			fmt.Println("got dhcp")
			parse_packet()				//if I need it, it would be put here, I think
			done <- true
			break
		}
	}
}


func sender() {
}


func parse_packet() {						//do I need a parse packet function?
}


func errorchecking() {
	//still need to add error checking
}
