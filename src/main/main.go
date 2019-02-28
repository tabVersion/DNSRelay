package main

import (
	"biu"
	"bufio"
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type DNSHeader struct {
	id            []byte
	qr            int64
	operationCode int64
	aa            int64
	tc            int64
	rd            int64
	ra            int64
	z             int64
	rCode         int64
	QDCount       int64
	ANCount       int64
	NSCount       int64
	ARCount       int64
}

type DNSQuestion struct {
	qname  []byte
	qtype  []byte
	qclass []byte
}

type DNSAnswer struct {
	aname  []byte
	atype  []byte
	aclass []byte
	ttl    int64
	rdlen  int64
	rdata  []byte
}

type DNSResponse struct {
	header   DNSHeader
	question DNSQuestion
	answer   DNSAnswer
}

var questionTypeDict = map[int64]string{
	1:   "A",
	2:   "NS",
	5:   "CNAME",
	6:   "SOA",
	11:  "WKS",
	12:  "PTR",
	13:  "HINFO",
	15:  "MX",
	28:  "AAAA",
	252: "AXFR",
	255: "ANY",
}

func getHeader(data []byte) DNSHeader {
	flags := data[2:4]

	flagsStr := biu.BytesToBinaryString(flags)

	header := &DNSHeader{
		id:            data[0:2],
		qr:            StringToInt64(flagsStr[1:2]),
		operationCode: StringToInt64(flagsStr[2:6]),
		aa:            StringToInt64(flagsStr[6:7]),
		tc:            StringToInt64(flagsStr[7:8]),
		rd:            StringToInt64(flagsStr[8:9]),
		ra:            StringToInt64(flagsStr[10:11]),
		z:             StringToInt64(flagsStr[11:14]),
		rCode:         StringToInt64(flagsStr[14:18]),
		QDCount:       BytesToInt64(data[4:6]),
		ANCount:       BytesToInt64(data[6:8]),
		NSCount:       BytesToInt64(data[6:8]),
		ARCount:       BytesToInt64(data[10:12]),
	}

	return *header
}

func getQuestion(data []byte) DNSQuestion {

	qnameBytes := data[12 : len(data)-4]

	question := &DNSQuestion{
		qname:  qnameBytes,
		qtype:  data[len(data)-4 : len(data)-2],
		qclass: data[len(data)-2 : len(data)],
	}
	debug("qname: %v\n", question.qname)
	return *question
}

func Forward(data []byte, remoteDNS string) []byte {
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP(remoteDNS),
		Port: 53,
	})
	if err != nil {
		log.Println("连接失败!", err)
		return nil
	}
	t := time.Now()

	socket.SetDeadline(t.Add(time.Duration(5 * time.Second)))

	defer socket.Close()
	// 发送数据
	_, err = socket.Write(data)
	if err != nil {
		log.Println("发送数据失败!", err)
		return nil
	}
	// 接收数据
	revdata := make([]byte, 4096)
	rn, remoteAddr, err := socket.ReadFromUDP(revdata)
	if err != nil {
		log.Println("从", remoteAddr, "””读取数据失败!", err)
		return nil
	}
	//log.Println(rn, remoteAddr)
	//log.Printf("%x\n", revdata[:rn])

	return revdata[:rn]
}

func readConfig(dnsListPath string) map[string]string {
	var dnsMap = map[string]string{}
	var dnsListFile, _ = os.OpenFile(dnsListPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	defer dnsListFile.Close()
	dnsListScanner := bufio.NewScanner(dnsListFile)
	for dnsListScanner.Scan() {
		ip := ""
		domain := ""

		dnsList := dnsListScanner.Text()

		if string([]byte(dnsList)[:1]) == "#" || dnsList == "" {
			continue
		}
		dnsList = strings.Split(dnsList, "#")[0]

		dnsArr := strings.Split(dnsList, " ")
		if len(dnsArr) >= 2 {
			for _, dnsStr := range dnsArr {
				if isIP(dnsStr) {
					ip = dnsStr
				} else {
					domain = dnsStr
				}
				if ip != "" && domain != "" {
					dnsMap[domain] = ip
				}
				domain = ""
			}
		} else {
			log.Printf("dns 配置错误，请检查：%s", dnsList)
		}

	}
	log.Printf("current dns setting: %q", dnsMap)
	if len(dnsMap) != 0 {
		return dnsMap
	}
	return nil
}

func cacheDNS(header DNSHeader, question DNSQuestion, ip string) []byte {

	response := DNSResponse{}

	response.header.id = header.id
	response.header.qr = 1
	response.header.operationCode = 0
	response.header.aa = 0
	response.header.tc = 0
	response.header.rd = 1
	response.header.ra = 0
	response.header.z = 0
	response.header.rCode = 0
	response.header.QDCount = 1
	response.header.ANCount = 1
	response.header.NSCount = 0
	response.header.ARCount = 0

	response.question = question

	response.answer.aname = question.qname
	response.answer.atype = question.qtype
	response.answer.aclass = question.qclass
	response.answer.ttl = 600
	response.answer.rdlen = 4
	response.answer.rdata = ipAddrToByte(ip)

	return reslove(response)

}

func reslove(response DNSResponse) []byte {
	buf := make([]byte, 30+len(response.question.qname)+2)
	offset := len(response.question.qname)

	buf[0] = response.header.id[0]
	buf[1] = response.header.id[1]

	buf[2] = byte(0x00 |
		response.header.qr<<7 |
		response.header.operationCode<<3 |
		response.header.aa<<2 |
		response.header.tc<<1 |
		response.header.rd)
	buf[3] = byte(0x00 |
		response.header.ra<<7 |
		response.header.z<<4 |
		response.header.rCode)
	buf[4] = byte(0x00)
	buf[5] = byte(0x00 |
		response.header.QDCount)
	buf[6] = byte(0x00)
	buf[7] = byte(0x00 |
		response.header.ANCount)
	buf[8] = byte(0x00)
	buf[9] = byte(0x00)
	buf[10] = byte(0x00)
	buf[11] = byte(0x00)

	writebytesToBuffer(buf, response.question.qname, 12)
	writebytesToBuffer(buf, response.question.qtype, 12+int64(offset))
	writebytesToBuffer(buf, response.question.qclass, 14+int64(offset))

	offset += 16
	writebytesToBuffer(buf, []byte{0xc0, 0x0c}, int64(offset))

	offset += 2
	writebytesToBuffer(buf, response.answer.atype, int64(offset))
	writebytesToBuffer(buf, response.answer.aclass, int64(offset)+2)
	writebytesToBuffer(buf, linkBytes([]byte{0x00, 0x00}, Int64ToBytes(response.answer.ttl)), int64(offset)+4)
	writebytesToBuffer(buf, Int64ToBytes(response.answer.rdlen), int64(offset)+8)
	writebytesToBuffer(buf, response.answer.rdata, int64(offset)+10)

	return buf
}

/*
func main() {
	var remoteDNS string
	var dnsListPath string
	flag.StringVar(&remoteDNS, "remoteDNS", "8.8.8.8", "Forwarding DNS server")
	flag.StringVar(&dnsListPath, "dnsListPath", "./dns-local.txt", "dns hook config file path")
	flag.Parse()

	dnsMap := readConfig(dnsListPath)

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53})

	if err != nil {
		log.Println(err)
		return
	}
	defer listener.Close()

	log.Println("Listening Local：" + listener.LocalAddr().String())

	data := make([]byte, 1024)

	for {
		n, remoteAddr, readErr := listener.ReadFromUDP(data)
		debug("get packet\n")

		header := getHeader(data[:n])
		question := getQuestion(data[:n])

		if readErr != nil {
			log.Printf("error during read: %s", readErr)
		}

		if dnsMap == nil || dnsMap[parseDomain(question.qname)] == "" {
			log.Printf("forward %s to %s", parseDomain(question.qname), remoteDNS)
			_, writeErr := listener.WriteToUDP(Forward(data[:n], remoteDNS), remoteAddr)

			if writeErr != nil {
				log.Printf("error during write: %s", writeErr)
			}
			continue
		}
		rsp := cacheDNS(header, question, dnsMap[parseDomain(question.qname)])
		_, writeErr := listener.WriteToUDP(rsp, remoteAddr)
		if writeErr != nil {
			log.Printf("error during write: %s", writeErr)
		} else {
			log.Printf("hook %s return %s", parseDomain(question.qname), dnsMap[parseDomain(question.qname)])
		}
	}
}
*/

func refuseDNS(header DNSHeader, question DNSQuestion, ip string) []byte {
	response := DNSResponse{}

	response.header.id = header.id
	response.header.qr = 1
	response.header.operationCode = 0
	response.header.aa = 1
	response.header.tc = 0
	response.header.rd = 1
	response.header.ra = 0
	response.header.z = 0
	response.header.rCode = 3
	response.header.QDCount = 1
	response.header.ANCount = 1
	response.header.NSCount = 0
	response.header.ARCount = 0

	response.question = question

	response.answer.aname = question.qname
	response.answer.atype = question.qtype
	response.answer.aclass = question.qclass
	response.answer.ttl = 600
	response.answer.rdlen = 4
	response.answer.rdata = ipAddrToByte(ip)

	return reslove(response)
}

func unsupportDNS(header DNSHeader, question DNSQuestion, ip string) []byte {
	response := DNSResponse{}

	response.header.id = header.id
	response.header.qr = 1
	response.header.operationCode = 0
	response.header.aa = 1
	response.header.tc = 0
	response.header.rd = 1
	response.header.ra = 0
	response.header.z = 0
	response.header.rCode = 4
	response.header.QDCount = 1
	response.header.ANCount = 1
	response.header.NSCount = 0
	response.header.ARCount = 0

	response.question = question

	response.answer.aname = question.qname
	response.answer.atype = question.qtype
	response.answer.aclass = question.qclass
	response.answer.ttl = 600
	response.answer.rdlen = 4
	response.answer.rdata = ipAddrToByte(ip)

	return reslove(response)
}

type byteTransefer struct {
	data []byte
	n    int
}

func main() {
	var remoteDNS string
	var dnsListPath string
	flag.StringVar(&remoteDNS, "remoteDNS", "8.8.8.8", "Forwarding DNS server")
	flag.StringVar(&dnsListPath, "dnsListPath", "./dns-local.txt", "dns hook config file path")
	flag.Parse()

	dnsMap := readConfig(dnsListPath)

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53})

	if err != nil {
		log.Println(err)
		return
	}
	defer listener.Close()

	log.Println("Listening Local：" + listener.LocalAddr().String())
	log.Println("[This DNS support ipv4 ONLY]")

	for {
		debug("start loop\n")
		data := make([]byte, 1024)
		n, remoteAddr, readErr := listener.ReadFromUDP(data)
		debug("get remoteAddr and n %+v, %d in channel", remoteAddr, n)
		if readErr != nil {
			log.Printf("error during read: %s\n", readErr)
		}

		go func(ch byteTransefer) {
			debug("start func\n")
			data := ch.data
			n := ch.n
			//log.Printf("get data and n in func %v, %d\n", data, n)
			header := getHeader(data[:n])
			question := getQuestion(data[:n])

			//debug("get qName %s\n", parseDomain(question.qname))
			//log.Printf("====> get qName %s and its cache %s\n", parseDomain(question.qname), dnsMap[parseDomain(question.qname)])

			//log.Printf("question %+v === type: %d\n", question, BytesToInt64(question.qtype))
			if BytesToInt64(question.qtype) != 1 {
				rep := unsupportDNS(header, question, "0.0.0.0")
				_, writeErr := listener.WriteToUDP(rep, remoteAddr)

				if writeErr != nil {
					log.Printf("error during write: %s", writeErr)
				} else {
					log.Printf("[unsupport protocal] %s ", parseDomain(question.qname))
				}
				return
			}

			if dnsMap == nil || dnsMap[parseDomain(question.qname)] == "" {
				log.Printf("forward %s to %s\n", parseDomain(question.qname), remoteDNS)
				_, writeErr := listener.WriteToUDP(Forward(data[:n], remoteDNS), remoteAddr)

				if writeErr != nil {
					log.Printf("error during write: %s\n", writeErr)
				}
				return
			} else if dnsMap[parseDomain(question.qname)] == "0.0.0.0" {
				rep := refuseDNS(header, question, dnsMap[parseDomain(question.qname)])
				_, writeErr := listener.WriteToUDP(rep, remoteAddr)

				if writeErr != nil {
					log.Printf("error during write: %s", writeErr)
				} else {
					log.Printf("[refuse] %s return %s", parseDomain(question.qname), dnsMap[parseDomain(question.qname)])
				}
				return
			} else {
				rsp := cacheDNS(header, question, dnsMap[parseDomain(question.qname)])
				_, writeErr := listener.WriteToUDP(rsp, remoteAddr)

				if writeErr != nil {
					log.Printf("error during write: %s", writeErr)
				} else {
					log.Printf("[cache] %s return %s", parseDomain(question.qname), dnsMap[parseDomain(question.qname)])
				}
			}
		}(byteTransefer{data: data, n: n})
	}
}
