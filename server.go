package main

import (
    "flag"
    "github.com/miekg/dns"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
)

var zone string
var proxyIp net.IP

func proxy(w dns.ResponseWriter, m *dns.Msg) *dns.Msg {
    if len(m.Question) == 0 {
        return nil
    }
    q := m.Question[0]
    if q.Name != zone {
        return nil
    }
    if q.Qtype != dns.TypeA {
        return nil
    }

    log.Printf("Proxying request for %s IN A from %s", q.Name, w.RemoteAddr())
    resp := new(dns.Msg)
    resp.SetReply(m)

    rr := new(dns.A)
    rr.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA,
        Class: dns.ClassINET, Ttl: 0}
    rr.A = proxyIp.To4()
    m.Answer = append(m.Answer, rr)
    return m
}

func handler(w dns.ResponseWriter, m *dns.Msg) {
    if proxiedMsg := proxy(w, m); proxiedMsg != nil {
        w.WriteMsg(proxiedMsg)
        return
    }

    c := new(dns.Client)
    c.Net = "udp"
    r, _, err := c.Exchange(m, "8.8.8.8:53")
    if err != nil {
        log.Print(err)
        return
    }
    log.Printf("Request passed from %s passed through", w.RemoteAddr())
    w.WriteMsg(r)
}

func main() {
    dns.HandleFunc(".", handler)

    flZone := flag.String("zone", "", "the zone to proxy")
    flIp := flag.String("ip", "", "ip address to answer with")
    flag.Parse()

    if len(*flZone) == 0 {
        log.Fatal("zone must be given")
    }
    if len(*flIp) == 0 {
        log.Fatal("ip must be given")
    }

    zone = *flZone
    if proxyIp = net.ParseIP(*flIp); proxyIp == nil {
        log.Fatalf("invalid IP address: %s", *flIp)
    }
    log.Printf("Proxying requests for zone: %s -> %s", zone, proxyIp)

    go func() {
        err := dns.ListenAndServe(":8053", "udp", nil)
        if err != nil {
            log.Fatal(err)
        }
    }()

    sig := make(chan os.Signal)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    for {
        select {
        case s := <-sig:
            log.Fatalf("Signal (%d) received, stopping\n", s)
        }
    }
}
