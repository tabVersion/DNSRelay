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
	"sync"
)

var epoch = time.Now()

var index_channel = make(chan int64, 20)

type DNSHeader struct { // 描述 DNS 报文结构
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

type DNSQuestion struct { // DNS 请求结构
	questionName  []byte
	questionType  []byte
	questionClass []byte
}

type DNSAnswer struct { // DNS 应答结构
	aname  []byte
	atype  []byte
	aclass []byte
	ttl    int64
	rdlen  int64
	rdata  []byte
}

type DNSResponse struct { // DNS 应答结构
	header   DNSHeader
	question DNSQuestion
	answer   DNSAnswer
}

var questionTypeDict = map[int64]string{ // 枚举请求类型
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

func getHeader(data []byte) DNSHeader { // 解析请求头部
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

func getQuestion(data []byte) DNSQuestion { // 解析请求地址

	qnameBytes := data[12 : len(data)-4]

	question := &DNSQuestion{
		questionName:  qnameBytes,
		questionType:  data[len(data)-4 : len(data)-2],
		questionClass: data[len(data)-2 : len(data)],
	}
	return *question
}

func Forward(data []byte, remoteDNS string, cur_new_id int64, origin_id []byte) []byte { // 控制转发
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{ // 创建 socket 连接
		IP:   net.ParseIP(remoteDNS),
		Port: 53,
	})
	if err != nil {
		debug(2,"connect failed!\n", err)
		flag := false
		for i := 0; i < 4; i++ {
			socket, err = net.DialUDP("udp4", nil, &net.UDPAddr{ // 创建 socket 连接
				IP:   net.ParseIP(remoteDNS),
				Port: 53,
			})
			if err != nil {
				flag = true
				break
			}
			debug(2,"connect failed!\n",err)
		}
		if !flag {
			return nil
		}
	}
	t := time.Now()

	socket.SetDeadline(t.Add(time.Duration(5 * time.Second))) // 设置超时时间

	defer socket.Close()

	// data[0] = Int64ToBytes(cur_new_id)[0]
	// data[1] = Int64ToBytes(cur_new_id)[1]

	dn, err := socket.Write(data)
	if err != nil {
		log.Println("send data failed!\n", err)
		return nil
	}
	debug(2,"SEND to %v    length: %d bytes\n",socket.RemoteAddr(),dn)	

	receiveData := make([]byte, 4096) // 创建缓冲区 大小为 4096 bytes
	rn, remoteAddr, err := socket.ReadFromUDP(receiveData)
	if err != nil {
		log.Println("from ", remoteAddr, " read data failed!\n", err)
		return nil
	}

	var mutex sync.Mutex
	mutex.Lock()
	_ = requestConvert[cur_new_id]
	mutex.Unlock()

	debug(2, "RECV from %v\n", remoteAddr)
	header := getHeader(receiveData[:rn])

	debug(2, "ID %X -> %X length: %d bytes %s\n",Int64ToBytes(cur_new_id), data[0:2], rn, DecimalByteSlice2HexString(receiveData[:rn]))
	debug(2, "\t\tID:%X , QR:%d , OPCODE:%d , AA:%d , TC:%d , RD:%d , RA: %d , Z: %d , RCODE: %d\n", header.id, header.qr, header.operationCode, header.aa, header.tc, header.rd, header.ra, header.z, header.rCode)
	debug(2, "\t\tQDCOUNT:%d , ANCOUNT:%d , NSCOUNT:%d , ARCOUNT:%d\n", header.QDCount, header.ANCount, header.NSCount, header.ARCount)

	receiveData[0] = origin_id[0]
	receiveData[1] = origin_id[1]

	return receiveData[:rn]
}

func readConfig(dnsListPath string) map[string]string { // 创建转发表
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
				if isIP(dnsStr) { // 识别是否是 IP 地址
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
			debug(2, "dns config error, please check %s", dnsList)
		}
	}
	debug(2, "current dns setting: \n") // 输出当前的 IP cache 包括缓存和拒绝服务的列表
	for domain := range dnsMap{
		debug(2,"%v    %v    \n",dnsMap[domain],domain)
	}
	if len(dnsMap) != 0 {
		return dnsMap // 确保返回的列表非空
	}
	return nil
}

func cacheDNS(header DNSHeader, question DNSQuestion, ip string) []byte { // 构造缓存中的 dns 报文
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

	response.answer.aname = question.questionName
	response.answer.atype = question.questionType
	response.answer.aclass = question.questionClass
	response.answer.ttl = 600
	response.answer.rdlen = 4
	response.answer.rdata = ipAddrToByte(ip)

	return reslove(response)
}

func reslove(response DNSResponse) []byte {
	buf := make([]byte, 30+len(response.question.questionName)+2)
	offset := len(response.question.questionName)

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

	writebytesToBuffer(buf, response.question.questionName, 12)
	writebytesToBuffer(buf, response.question.questionType, 12+int64(offset))
	writebytesToBuffer(buf, response.question.questionClass, 14+int64(offset))

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

func refuseDNS(header DNSHeader, question DNSQuestion, ip string) []byte { // 创建拒绝服务的 dns 报文
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

	response.answer.aname = question.questionName
	response.answer.atype = question.questionType
	response.answer.aclass = question.questionClass
	response.answer.ttl = 600
	response.answer.rdlen = 4
	response.answer.rdata = ipAddrToByte(ip)

	return reslove(response)
}

func unsupportDNS(header DNSHeader, question DNSQuestion, ip string) []byte { // 创建不支持协议的 dns 报文
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

	response.answer.aname = question.questionName
	response.answer.atype = question.questionType
	response.answer.aclass = question.questionClass
	response.answer.ttl = 600
	response.answer.rdlen = 4
	response.answer.rdata = ipAddrToByte(ip)

	return reslove(response)
}

type byteTransefer struct {
	data []byte
	n    int
}

var requestConvert = map[int64] int64 {}

func main() {
	epoch = time.Now()
	var mutex sync.Mutex
	var remoteDNS string
	var dnsListPath string
	var d bool
	var dd bool
	flag.BoolVar(&d, "d", false, "brief log")
	flag.BoolVar(&dd, "dd", false, "complete log")
	flag.StringVar(&remoteDNS, "remoteDNS", "8.8.8.8", "Forwarding DNS server")
	flag.StringVar(&dnsListPath, "dnsListPath", "./dns-local.txt", "dns relay config file path")
	flag.Parse() // 解析传入参数

	if d {
		debugEnabled = true
		debugLevel = 1
		log.Println("Debug Level : 1")
	} else if dd {
		debugEnabled = true
		debugLevel = 2
		log.Println("Debug Level : 2")
	}else{
		log.Println("Debug Level : 0")
	}

	flag.Parse() // 解析传入参数

	dnsMap := readConfig(dnsListPath)

	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}) // 开始监听 127.0.0.1:53

	if err != nil {
		log.Println(err)
		return
	}
	defer listener.Close()

	log.Println("Listening Local: " + listener.LocalAddr().String())
	log.Println("[This DNS support ipv4 ONLY]")
	// debug(2, "%d\n", BytesToInt64_fix(Int64ToBytes_fix(19)))

	var requestIndex int64
	requestIndex = 0

	for {
		data := make([]byte, 1024)
		n, remoteAddr, readErr := listener.ReadFromUDP(data)
		if readErr != nil {
			debug(2, "error during read: %s\n", readErr)
		}
		debug(2, "RECV from %v\n", remoteAddr)
		// start a thread once hearing from UDP
		go func(ch byteTransefer) { // 多线程查询
			//debug(2,"start func\n")
			data := ch.data
			n := ch.n
			header := getHeader(data[:n])
			question := getQuestion(data[:n])

			index_channel <- BytesToInt64(header.id)
			//debug(2,"message %X in channel\n", header.id)

			debug(1, "%v    TYPE:%d    CLASS:%d\n", parseDomain(question.questionName), question.questionType[1], BytesToInt64(question.questionClass))
			if BytesToInt64(question.questionType) != 1 { // 检查协议 v4 only
				rep := unsupportDNS(header, question, "0.0.0.0")
				_, writeErr := listener.WriteToUDP(rep, remoteAddr)

				if writeErr != nil {
					debug(2, "error during write: %s\n", writeErr)
				} else {
					debug(2, "[unsupport protocal] %s\n ", parseDomain(question.questionName))
				}
				_ = <-index_channel
				return // 若协议不匹配直接丢弃
			}
			debug(2, "length:%d bytes    %s\n", n, DecimalByteSlice2HexString(data[:n]))
			debug(2, "\t\tID:%X , QR:%d , OPCODE:%d , AA:%d , TC:%d , RD:%d , RA: %d , Z: %d , RCODE: %d\n", 
				header.id, header.qr, header.operationCode, header.aa, header.tc, header.rd, header.ra, header.z, header.rCode)
			debug(2, "\t\tQDCOUNT:%d , ANCOUNT:%d , NSCOUNT:%d , ARCOUNT:%d\n", header.QDCount, header.ANCount, header.NSCount, header.ARCount)
			debug(2, "\t\t%v    TYPE:%d    CLASS:%d\n", parseDomain(question.questionName), question.questionType[1], BytesToInt64(question.questionClass))

			if dnsMap == nil || dnsMap[parseDomain(question.questionName)] == "" { // 表中没有记录的项 进行转发 ===> 中继

				mutex.Lock()
				cur_new_id := requestIndex
				requestConvert[cur_new_id] = BytesToInt64(header.id)
				requestIndex = (requestIndex + 1) % 100
				mutex.Unlock()

				debug(2, "forward %s to %s ID %X -> %X\n", parseDomain(question.questionName), remoteDNS, header.id, Int64ToBytes(cur_new_id))
				dn, writeErr := listener.WriteToUDP(Forward(data[:n], remoteDNS, cur_new_id, header.id), remoteAddr)

				if writeErr != nil {
					debug(2, "error during write: %s\n", writeErr)
				}else{
					debug(2,"SEND to %v    length: %d bytes\n",remoteAddr,dn)	
				}
				_ = <-index_channel
				return
			} else if dnsMap[parseDomain(question.questionName)] == "0.0.0.0" { // 查表看看是不是拒绝服务的项 回复拒绝服务
				rep := refuseDNS(header, question, dnsMap[parseDomain(question.questionName)])
				dn, writeErr := listener.WriteToUDP(rep, remoteAddr)

				if writeErr != nil {
					debug(2, "error during write: %s\n", writeErr)
				} else {
					debug(2,"SEND to %v    length: %d bytes\n",remoteAddr,dn)	
					debug(2, "[refuse] %s return %s\n", parseDomain(question.questionName), dnsMap[parseDomain(question.questionName)])
				}
				_ = <-index_channel
				return
			} else {
				rsp := cacheDNS(header, question, dnsMap[parseDomain(question.questionName)]) // 表中有且不是 拒绝服务的项 ===> 直接返回 服务器功能
				dn, writeErr := listener.WriteToUDP(rsp, remoteAddr)

				if writeErr != nil {
					debug(2, "error during write: %s\n", writeErr)
				} else {
					debug(2,"SEND to %v    length: %d bytes\n",remoteAddr,dn)	
					debug(2, "[cache] %s return %s\n", parseDomain(question.questionName), dnsMap[parseDomain(question.questionName)])
				}
			}
			_ = <-index_channel
		}(byteTransefer{data: data, n: n})
	}
}
