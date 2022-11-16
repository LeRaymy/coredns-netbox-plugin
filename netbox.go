// Copyright 2020 Oz Tiram <oz.tiram@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netbox

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/plugin/pkg/fall"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("netbox")

// Structure for the plugin
type Netbox struct {
	Url    string
	Token  string
	Next   plugin.Handler
	TTL    time.Duration
	Fall   fall.F
	Zones  []string
	Client *http.Client
}

// constants to match IP address family used by NetBox
const (
	familyIP4 = 4
	familyIP6 = 6
)

// ServeDNS implements the plugin.Handler interface. This method is called for every dns request.
func (n *Netbox) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var (
		err error
		records RecordsList
	)

	state := request.Request{W: w, Req: r}
	dns_type := GetDnsType(state.QType())
	log.Info("Request received from " + GetOutboundIP().String() + " for " + state.QName() + " with type " + dns_type)

	// only handle zones we are configured to respond for
	zone := plugin.Zones(n.Zones).Matches(state.Name())
	if zone == "" {
		return plugin.NextOrFailure(n.Name(), n.Next, ctx, w, r)
	}

	qname := state.Name()

	// check record type here and bail out if not A or AAAA
	if state.QType() != dns.TypeA && state.QType() != dns.TypeAAAA {
		// always fallthrough if configured
		if n.Fall.Through(qname) {
			return plugin.NextOrFailure(n.Name(), n.Next, ctx, w, r)
		}

		// otherwise return SERVFAIL here without fallthrough
		return dnserror(dns.RcodeServerFailure, state, err)
	}

	// Export metric with the server label set to the current
	// server handling the request.
	requestCount.WithLabelValues(metrics.WithServer(ctx)).Inc()

	answers := []dns.RR{}

	records, err = n.query(strings.TrimSuffix(qname, "." + zone), dns_type)

	// Handle according to DNS Type
	switch state.QType() {
	case dns.TypeA:
		answers = a(qname, uint32(n.TTL), records)
	case dns.TypeAAAA:
		answers = aaaa(qname, uint32(n.TTL), records)
	case dns.TypeMX:
		answers = mx(qname, uint32(n.TTL), records)
	case dns.TypeTXT:
		answers = txt(qname, uint32(n.TTL), records)
	case dns.TypeCNAME:
		answers = cname(qname, uint32(n.TTL), records)
	case dns.TypeSOA:
		answers = soa(qname, uint32(n.TTL), records)
	case dns.TypeNS:
		answers = ns(qname, uint32(n.TTL), records)
	case dns.TypeSRV:
		answers = srv(qname, uint32(n.TTL), records)
	case dns.TypePTR:
		answers = ptr(qname, uint32(n.TTL), records)
	case dns.TypeSPF:
		answers = spf(qname, uint32(n.TTL), records)
	}

	if len(answers) == 0 {
		// always fallthrough if configured
		if n.Fall.Through(qname) {
			return plugin.NextOrFailure(n.Name(), n.Next, ctx, w, r)
		}

		if err != nil {
			// return SERVFAIL here without fallthrough
			return dnserror(dns.RcodeServerFailure, state, err)
		}

		// otherwise return NXDOMAIN
		return dnserror(dns.RcodeNameError, state, nil)
	}

	// create DNS response
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Answer = answers

	// send response back to client
	_ = w.WriteMsg(m)

	// signal response sent back to client
	return dns.RcodeSuccess, nil
}

// Name implements the Handler interface.
func (n *Netbox) Name() string { return "netbox" }

// a takes a slice of net.IPs and returns a slice of A RRs.
func a(zone string, ttl uint32, response RecordsList) []dns.RR {
	answers := make([]dns.RR, len(response.Records))

	for i, record := range response.Records {
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
		// Parsing IP in IPv4 format
		r.A = net.ParseIP(string(record.Value)).To4()
		answers[i] = r
	}
	return answers
}

// aaaa takes a slice of net.IPs and returns a slice of AAAA RRs.
func aaaa(zone string, ttl uint32, response RecordsList) []dns.RR {
	answers := make([]dns.RR, len(response.Records))

	for i, record := range response.Records {
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
		// Parsing IP in IPv6 format
		r.AAAA = net.ParseIP(string(record.Value)).To16()
		answers[i] = r
	}
	return answers
}

// mx takes a slice of net.IPs and returns a slice of MX RRs.
func mx(zone string, ttl uint32, response RecordsList) []dns.RR {
	answers := make([]dns.RR, len(response.Records))

	for i, record := range response.Records {
		r := new(dns.MX)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl}
		r.Mx = record.Value + "."
		answers[i] = r
	}
	return answers
}

// txt takes a slice of net.IPs and returns a slice of TXT RRs.
func txt(zone string, ttl uint32, response RecordsList) []dns.RR {
	answers := make([]dns.RR, len(response.Records))

	for i, record := range response.Records {
		r := new(dns.TXT)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl}
		r.Txt = []string{record.Value + "."}
		answers[i] = r
	}
	return answers
}

// cname takes a slice of net.IPs and returns a slice of CNAME RRs.
func cname(zone string, ttl uint32, response RecordsList) []dns.RR {
	answers := make([]dns.RR, len(response.Records))

	for i, record := range response.Records {
		r := new(dns.CNAME)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl}
		r.Target = record.Value + "."
		answers[i] = r
	}
	return answers
}

// soa takes a slice of net.IPs and returns a slice of SOA RRs.
func soa(zone string, ttl uint32, response RecordsList) []dns.RR {
	answers := make([]dns.RR, len(response.Records))

	for i, record := range response.Records {
		r := new(dns.SOA)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl}
		r.Ns = record.Value + "."
		r.Mbox = record.Value + "."
		answers[i] = r
	}
	return answers
}

// ns takes a slice of net.IPs and returns a slice of NS RRs.
func ns(zone string, ttl uint32, response RecordsList) []dns.RR {
	answers := make([]dns.RR, len(response.Records))

	for i, record := range response.Records {
		r := new(dns.NS)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl}
		r.Ns = record.Value + "."
		answers[i] = r
	}
	return answers
}

// srv takes a slice of net.IPs and returns a slice of SRV RRs.
func srv(zone string, ttl uint32, response RecordsList) []dns.RR {
	answers := make([]dns.RR, len(response.Records))

	for i, record := range response.Records {
		r := new(dns.SRV)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl}
		r.Target = record.Value + "."
		answers[i] = r
	}
	return answers
}

// ptr takes a slice of net.IPs and returns a slice of PTR RRs.
func ptr(zone string, ttl uint32, response RecordsList) []dns.RR {
	answers := make([]dns.RR, len(response.Records))

	for i, record := range response.Records {
		r := new(dns.PTR)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
		r.Ptr = record.Value + "."
		answers[i] = r
	}
	return answers
}

// spf takes a slice of net.IPs and returns a slice of PTR RRs.
func spf(zone string, ttl uint32, response RecordsList) []dns.RR {
	answers := make([]dns.RR, len(response.Records))

	for i, record := range response.Records {
		r := new(dns.SPF)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
		r.Txt = []string{record.Value + "."}
		answers[i] = r
	}
	return answers
}

// dnserror writes a DNS error response back to the client. Based on plugin.BackendError
func dnserror(rcode int, state request.Request, err error) (int, error) {
	m := new(dns.Msg)
	m.SetRcode(state.Req, rcode)
	m.Authoritative = true

	// send response
	_ = state.W.WriteMsg(m)

	// return success as the rcode to signal we have written to the client.
	return dns.RcodeSuccess, err
}

// This fonction returns the local IP address
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Error(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// This fonction converts the uint16 to string
func GetDnsType(qtype uint16) string {

	switch qtype {
	case dns.TypeA:
		return "A"

	case dns.TypeAAAA:
		return "AAAA"

	case dns.TypeMX:
		return "MX"

	case dns.TypeTXT:
		return "TXT"

	case dns.TypeCNAME:
		return "CNAME"

	case dns.TypeSOA:
		return "SOA"

	case dns.TypeNS:
		return "NS"

	case dns.TypeSRV:
		return "SRV"

	case dns.TypePTR:
		return "PTR"

	case dns.TypeSPF:
		return "SPF"
	}
	return ""
}
