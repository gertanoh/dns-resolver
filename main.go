package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/gertanoh/dns-resolver/internal/parser"
)

// Map of question and clientIps
var registryMap = map[parser.Question]string{}

func main() {

	var port int
	flag.IntVar(&port, "p", 53, "port server is listenning to")
	flag.Parse()

	// Resolve UDP address
	addr, err := net.ResolveUDPAddr("udp", ":"+strconv.Itoa(port))
	if err != nil {
		log.Println("Error resolving address: ", err)
		os.Exit(1)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Error listenning on UDP port:", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Listenning on UDP port %d\n", port)

	buffer := make([]byte, 512) // DNS messages are lower than 512

	for {
		// Read from connection
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println(err)
			continue
		}
		question, err := parser.Read(buffer, n)
		if err != nil {
			log.Println(err)
			continue
		}

		for _, q := range question.Questions {
			registryMap[q] = clientAddr.String()
		}

		// forward request to Google DNS
		googleDNS := "8.8.8.8:53"
		forwardConn, err := net.Dial("udp", googleDNS)
		if err != nil {
			log.Printf("Fail to dial Google DNS : %v", err)
			continue
		}
		// Forward request to Google DNS
		_, err = forwardConn.Write(buffer)
		if err != nil {
			log.Printf("Failed to write to Google's DNS server: %v", err)
			forwardConn.Close()
			continue
		}

		// Get the answer
		answerCount, err := forwardConn.Read(buffer)
		if err != nil {
			log.Printf("Failed to read from Google's DNS server: %v", err)
			forwardConn.Close()
			continue
		}
		forwardConn.Close()

		fmt.Println("Answer")
		parser.Read(buffer, answerCount)
		conn.WriteToUDP(buffer[:answerCount], clientAddr)
	}
}
