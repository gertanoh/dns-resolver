package parser

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type Header struct {
	ID      uint16
	Flags   uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

type Question struct {
	QName  string
	QType  uint16
	QClass uint16
}

type Resource struct {
	RName    string
	RType    uint16
	RClass   uint16
	RTtl     uint32 // time in seconds before cache for this record is invalidated. 0 means that it shall not be cached
	RDlength uint16 // specify the length of r data field
	RData    []byte // This can be an IP address for A records, a hostname for CNAME
}

type Payload struct {
	Header      Header
	Questions   []Question
	Answers     []Resource
	Authorities []Resource
	Additionals []Resource
}

// Using network byte order, which is big endian, see
// https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.2

func parseHeader(buffer []byte) Header {
	return Header{
		ID:      binary.BigEndian.Uint16(buffer[0:2]),
		Flags:   binary.BigEndian.Uint16(buffer[2:4]),
		QdCount: binary.BigEndian.Uint16(buffer[4:6]),
		AnCount: binary.BigEndian.Uint16(buffer[6:8]),
		NsCount: binary.BigEndian.Uint16(buffer[8:10]),
		ArCount: binary.BigEndian.Uint16(buffer[10:12]),
	}
}

func parseResource(buffer []byte, offset int) (Resource, int) {
	// Parse RNAME
	rname, n := parseDomainName(buffer, offset)
	offset += n

	// Parse RTYPE
	rtype := binary.BigEndian.Uint16(buffer[offset : offset+2])
	offset += 2

	// Parse RCLASS
	rclass := binary.BigEndian.Uint16(buffer[offset : offset+2])
	offset += 2

	// parse TTL
	rttl := binary.BigEndian.Uint32(buffer[offset : offset+4])
	offset += 4

	// decode rData based on Rtype and Rclass
	// parse RDLength
	rdlen := binary.BigEndian.Uint16(buffer[offset : offset+2])
	offset += 2

	var rddata []byte

	// NS record
	if rtype == 2 && rclass == 1 {
		rdataBuffer := buffer[offset : offset+int(rdlen)]
		domainName, _ := parseDomainName(rdataBuffer, 0)
		rddata = []byte(domainName)
	} else {
		rddata = buffer[offset : offset+int(rdlen)]
	}
	offset += int(rdlen)

	return Resource{RName: rname, RType: rtype, RClass: rclass, RTtl: rttl, RDlength: rdlen, RData: rddata}, offset
}

// parseQuestion parses the question section of a DNS message
func parseQuestion(buffer []byte, offset int) (Question, int) {
	// Parse QNAME
	qname, n := parseDomainName(buffer, offset)
	offset += n

	// Parse QTYPE
	qtype := binary.BigEndian.Uint16(buffer[offset : offset+2])
	offset += 2

	// Parse QCLASS
	qclass := binary.BigEndian.Uint16(buffer[offset : offset+2])
	offset += 2

	return Question{QName: qname, QType: qtype, QClass: qclass}, offset
}

// https://cabulous.medium.com/dns-message-how-to-read-query-and-response-message-cfebcb4fe817
// It handles normal labels and compressed labels.
func parseDomainName(buffer []byte, offset int) (qname string, n int) {
	labels := ""
	startOff := offset

	for {
			len := int(buffer[startOff])
		// length 192 denotes a pointer to a previous seen domain name, use next octet to get length of domain inside buffer pointer to previous seen messages

		if len == 192 {
			label, _ := parseDomainName(buffer, int(buffer[startOff+1]))
			labels += label
			// jump over pointer and offset
			startOff += 2
			break
		} else {
			label := string(buffer[startOff+1 : startOff+1+len])
			startOff += len + 1
			if buffer[len] == 0 {
				labels += label
				startOff++
				break
			} else {
				labels += label + "."
			}
		}
	}
	qname = labels
	n = startOff - offset
	return
}

func Read(buffer []byte, n int) (Payload, error) {

	var payload Payload

	// Print each byte in hexadecimal and decimal format
	for i, b := range buffer[:n] {
		fmt.Printf("Byte %d: %02x (Hex) | %d (Dec)\n", i, b, b)
	}

	if len(buffer) < 12 {
		err := errors.New("message Header does not meet the minimun required length")
		return payload, err
	}

	payload.Header = parseHeader(buffer[:12])
	fmt.Printf("Header: %+v\n", payload.Header)

	index := 12
	var i uint16
	for i = 0; i < uint16(payload.Header.QdCount); i++ {
		q, newIndex := parseQuestion(buffer, index)
		index = newIndex
		payload.Questions = append(payload.Questions, q)
	}

	for i = 0; i < uint16(payload.Header.AnCount); i++ {
		answer, newIndex := parseResource(buffer, index)
		index = newIndex
		payload.Answers = append(payload.Answers, answer)
	}

	for i = 0; i < uint16(payload.Header.NsCount); i++ {
		authority, newIndex := parseResource(buffer, index)
		index = newIndex
		payload.Authorities = append(payload.Authorities, authority)
	}

	for i = 0; i < uint16(payload.Header.ArCount); i++ {
		additional, newIndex := parseResource(buffer, index)
		index = newIndex
		payload.Additionals = append(payload.Additionals, additional)
	}
	for _, b := range payload.Questions {
		fmt.Printf("Questions :%+v\n", b)
	}
	for _, b := range payload.Answers {
		fmt.Printf("Answers :%+v\n", b)
	}
	return payload, nil
}
