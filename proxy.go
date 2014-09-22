package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/miekg/dns"
)

const resolvConf = "/etc/resolv.conf"

var (
	zones      map[string]net.IP
	nameserver string
	listen     = flag.String("a", ":53", "DNS listen address")
	netMask    = flag.Int("m", 24, "netmask in CIDR notation")
	netFirst   = flag.String("f", "10.0.1.20", "first adress")
	netLast    = flag.String("l", "10.0.1.80", "last adress")
	dev        = flag.String("d", "eth0", "interface to configure ips on")
	ns         = flag.String("s", "", "nameserver to use (empty: parse resolv.conf)")
)

func ProxyMsg(m *dns.Msg) *dns.Msg {
	if len(m.Question) == 0 {
		return nil
	}
	q := m.Question[0]

	ip, exists := zones[q.Name]
	if !exists {
		return nil
	}

	if q.Qtype != dns.TypeA {
		response := new(dns.Msg)
		response.SetReply(m)
		return response
	}

	response := new(dns.Msg)
	response.SetReply(m)

	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA,
		Class: dns.ClassINET, Ttl: 0}
	rr.A = ip.To4()
	response.Answer = append(m.Answer, rr)

	return response
}

func dnsHandler(w dns.ResponseWriter, m *dns.Msg) {
	if msg := ProxyMsg(m); msg != nil {
		log.Printf("Proxying request for %s IN A from %s",
			msg.Question[0].Name, w.RemoteAddr())
		w.WriteMsg(msg)
		return
	}

	c := new(dns.Client)
	c.Net = "udp"
	r, _, err := c.Exchange(m, nameserver)
	if err != nil {
		log.Print(err)
		return
	}
	w.WriteMsg(r)
}

func copy(dst io.ReadWriteCloser, src io.ReadWriteCloser) {
	if _, err := io.Copy(dst, src); err != nil {
		log.Print(err)
	}
	dst.Close()
	src.Close()
}

func handleConn(local net.Conn, remoteAddr string) {
	remote, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Printf("Failed to connect to %s: %s", remoteAddr, err)
		return
	}
	go copy(local, remote)
	go copy(remote, local)
}

func tcpProxy(listenAddr string, remoteAddr string) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Print(err)
		}
		go handleConn(conn, remoteAddr)
	}
}

func listenAndServe() {
	go func() {
		err := dns.ListenAndServe(*listen, "udp", dns.HandlerFunc(dnsHandler))
		if err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		err := dns.ListenAndServe(*listen, "tcp", dns.HandlerFunc(dnsHandler))
		if err != nil {
			log.Fatal(err)
		}
	}()
	for zone, ip := range zones {
		log.Printf("+ %s -> %s", ip.String(), zone)
		cmd := exec.Command("ip", "addr", "add", ip.String(), "dev", *dev)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Fatalf("Couldn't add ip address '%s': \n%s", err, out)
		}
		go tcpProxy(ip.String()+":80", zone+":80")
		go tcpProxy(ip.String()+":443", zone+":443")
	}
}

func printfErr(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(2)
}

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		printfErr("usage: %s zone [zone ...]", os.Args[0])
	}

	mask := net.CIDRMask(*netMask, 32)
	ip := net.ParseIP(*netFirst)
	last := net.ParseIP(*netLast)
	if bytes.Compare(ip, last) > 0 {
		printfErr("first address must be lower than last address")
	}
	if bytes.Compare(ip.Mask(mask), last.Mask(mask)) != 0 {
		printfErr("Masks not identical: %c != %c", ip.Mask(mask), last.Mask(mask))
	}

	if *ns == "" {
		conf, err := dns.ClientConfigFromFile(resolvConf)
		if err != nil {
			printfErr("Error reading %s: %s", resolvConf, err)
		}
		if len(conf.Servers) == 0 {
			printfErr("No nameservers in %s found", resolvConf)
		}
		nameserver = fmt.Sprintf("%s:%s", conf.Servers[0], conf.Port)
	} else {
		nameserver = *ns
	}

	zones = make(map[string]net.IP, flag.NArg())
	for _, z := range flag.Args() {
		if bytes.Compare(ip, last) > 0 {
			log.Fatal("Not enough adresses in pool %s-%s", *netFirst, *netLast)
		}
		zone := dns.Fqdn(z)
		zones[zone] = append([]byte(nil), []byte(ip)...)
		log.Printf("Answering %s with %s", zone, ip)
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] > 0 {
				break
			}
		}
	}

	listenAndServe()

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case s := <-sig:
			log.Printf("Signal (%d) received, cleaning up\n", s)
			for zone, ip := range zones {
				log.Printf("- %s -> %s", ip.String(), zone)
				if err := exec.Command("ip", "addr", "del", ip.String(), "dev", *dev).Run(); err != nil {
					log.Printf("Error couldn't remove ip from interface: %s", err)
				}
			}
			os.Exit(0)
		}
	}
}
