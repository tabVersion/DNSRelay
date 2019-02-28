package main

import (
	"biu"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
)

const debugEnanled = false

func debug(format string, a ...interface{}) (n int, err error) {
	if debugEnanled {
		log.Printf("DEBUG:")
		n, err = fmt.Printf(format)
	}
	return
}

func ipAddrToByte(ipAddr string) []byte {
	bits := strings.Split(ipAddr, ".")
	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	return []byte{byte(b0), byte(b1), byte(b2), byte(b3)}
}

//域名解析
func parseDomain(buf []byte) string {
	parts := make([]string, 0)
	for i := 0; i < len(buf); {
		len := int(buf[i])

		if len == 0 {
			break
		}

		offset := i + 1
		parts = append(parts, string(buf[offset:offset+len]))

		i = offset + len
	}

	return strings.Join(parts, ".")
}

//将一个 byte 数组写入另一个 byte 数组
func writebytesToBuffer(buffer []byte, buf []byte, n int64) []byte {
	for _, b := range buf {
		buffer[n] = b
		n++
	}
	return buffer
}

//连接两个 byte 数组，并返回一个新的byte数组
func linkBytes(b1 []byte, b2 []byte) []byte {
	var buf bytes.Buffer
	buf.Write(b1)
	buf.Write(b2)
	return buf.Bytes()
}

//int64转 byte 数组
func Int64ToBytes(i int64) []byte {
	b_buf := bytes.NewBuffer([]byte{})
	binary.Write(b_buf, binary.BigEndian, i)
	return b_buf.Bytes()[len(b_buf.Bytes())-2:]
}

//byte 数组转 int64
func BytesToInt64(buf []byte) int64 {
	bufStr := biu.BytesToBinaryString(buf)
	bufint64, _ := strconv.ParseInt(bufStr[len(bufStr)-5:len(bufStr)-1], 10, 64)
	return bufint64
}

//字符串转 int64
func StringToInt64(str string) int64 {
	intStr, _ := strconv.ParseInt(str, 10, 64)
	return intStr
}

//正则判断字符串是否为 IP
func isIP(str string) bool {
	ipRe := regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	return ipRe.MatchString(str)
}

//判断字符串是否为域名
func isDomain(str string) bool {
	domainRe := regexp.MustCompile(`([a-z0-9--]{1,200})\.([a-z]{2,10})(\.[a-z]{2,10})?`)
	return domainRe.MatchString(str)
}
