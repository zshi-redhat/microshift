/*
Copyright © 2021 Microshift Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package server

import (
	"net"
	"sync"

	"github.com/miekg/dns"
	"k8s.io/klog/v2"
)

const defaultTTL = 120

type Resolver struct {
	sync.Mutex
	domain map[string][]net.IP
}

func NewResolver() *Resolver {
	return &Resolver{
		domain: map[string][]net.IP{},
	}
}

func (r *Resolver) AddDomain(name string, ipStrs []string) {
	r.Lock()
	defer r.Unlock()
	var ips []net.IP

	for _, ip := range ipStrs {
		ips = append(ips, net.ParseIP(ip))
	}
	r.domain[name] = ips
	klog.Infof("resolver domain: %v ", r.domain)
}

func (r *Resolver) DeleteDomain(name string) {
	r.Lock()
	defer r.Unlock()
	delete(r.domain, name)
	klog.Infof("resolver domain: %v ", r.domain)
}

func (r *Resolver) HasDomain(name string) bool {
	r.Lock()
	defer r.Unlock()
	_, ok := r.domain[name]
	return ok
}

func (r *Resolver) Answer(q dns.Question) []dns.RR {
	klog.Infof("answering dns: %v ", q)
	r.Lock()
	defer r.Unlock()

	switch q.Qtype {
	case dns.TypeA:
		return r.answerARecord(q.Name)
	case dns.TypeAAAA:
		return r.answerAAAARecord(q.Name)
	}

	return nil
}

func (r *Resolver) answerARecord(name string) (rr []dns.RR) {
	klog.Infof("answering A record: %v ", name)
	for _, ip4 := range r.getIPs(name, net.IPv4len) {
		rr = append(rr, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
			A:   ip4,
		})
	}
	klog.Infof("answering A rr: %v ", rr)
	return rr
}

func (r *Resolver) answerAAAARecord(name string) (rr []dns.RR) {
	klog.Infof("answering AAAA record: %v ", name)
	for _, ip6 := range r.getIPs(name, net.IPv6len) {
		rr = append(rr, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: defaultTTL},
			AAAA: ip6,
		})
	}
	klog.Infof("answering AAAA rr: %v ", rr)
	return rr
}

func (r *Resolver) getIPs(name string, ipvlen int) []net.IP {
	klog.Infof("get IPs")
	ips, ok := r.domain[name]
	klog.Infof("len of ips: %d, ok: %v", len(ips), ok)
	if !ok || len(ips) == 0 {
		return nil
	}

	var filteredIps []net.IP

	for _, ip := range ips {
		klog.Infof("ip: %v", ip)
		switch ipvlen {
		case net.IPv4len:
			klog.Infof("ipv4 len")
			if ip4 := ip.To4(); ip4 != nil {
				klog.Infof("ipv4: %v", ip4)
				filteredIps = append(filteredIps, ip4)
			}
			klog.Infof("ipv4 == nil")

		case net.IPv6len:
			klog.Infof("ipv6 len")
			if ip4 := ip.To4(); ip4 != nil {
				klog.Infof("ip4 in ipv6 len")
				// net.To16 will convert ipv4 addresses to ::ffff:ipv4
				continue
			}
			if ip16 := ip.To16(); ip16 != nil {
				klog.Infof("ip16: %v", ip16)
				filteredIps = append(filteredIps, ip16)
			}
			klog.Infof("ip16 == nil")
		}
	}
	klog.Infof("filtered ips: %v", filteredIps)
	return filteredIps
}
