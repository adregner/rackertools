
import re
import sys

sys.path.append('vendor/')

import dns.resolver
import dns.reversename
from whois import NICClient

DOMAIN_CACHE = {}
NIC_CLIENT = None

def _clean_query(domain, rtype):
    answer = ()
    try:
        answer = dns.resolver.query(domain, rtype)
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.Timeout:
        pass
    return answer

def _cache_result(name, rtype=""):
    global DOMAIN_CACHE
    cache_key = "%s\0%s" % (name, rtype) if rtype else name
    if cache_key in DOMAIN_CACHE:
        # cache hit
        return DOMAIN_CACHE[cache_key]
    else:
        if rtype:
            # query is for DNS records
            if rtype == 'PTR':
                DOMAIN_CACHE[cache_key] = _get_ptr(name)
            else:
                DOMAIN_CACHE[cache_key] = _clean_query(name, rtype)
            return DOMAIN_CACHE[cache_key]
        else:
            #query is for a isp of an ip address
            DOMAIN_CACHE[cache_key] = _get_isp(name)
            return DOMAIN_CACHE[cache_key]

def _get_ptr(ip_address):
    reverse = _clean_query(dns.reversename.from_address(ip_address), 'PTR')
    ptr = reverse[0].target if reverse else "NO PTR RECORD"
    return ptr

def _get_isp(ip_address):
    global NIC_CLIENT
    isps = {}
    whois_response = NIC_CLIENT.whois_lookup({}, "n %s"%ip_address, NICClient.WHOIS_RECURSE)
    for line in whois_response.split("\n"):
        m = re.search('(.+) \((NET-[0-9-]+)\)', line)
        if m:
            isps[m.group(2)] = m.group(1)
    nets = isps.keys()
    nets.sort()
    return isps[nets[-1]]

def run(args):
    global NIC_CLIENT
    
    if NIC_CLIENT is None:
        NIC_CLIENT = NICClient()
    
    for domain in args:
        print '------------', domain, '------------'
        
        ns = _cache_result(domain, 'NS')
        a = _cache_result(domain, 'A')
        cname = _cache_result(domain, 'CNAME')
        mx = _cache_result(domain, 'MX')
        txt = _cache_result(domain, 'TXT')

        if ns:
            for rdata in ns:
                print "NS =", rdata.target
        else:
            print "NO NS RECORD"

        print

        if a:
            for rdata in a:
                print "A = %s (%s)" % (rdata.address, _cache_result(rdata.address, 'PTR'))
                print "    %s" % _cache_result(rdata.address)
        else:
            print "NO A RECORDS"

        print

        if cname:
            for rdata in cname:
                print "CNAME = %s" % rdata.target
                args.append(rdata.target)
        else:
            print "NO CNAME RECORDS"

        print

        if mx:
            mxers = {}
            for rdata in mx:
                if rdata.preference not in mxers:
                    mxers[rdata.preference] = []
                mxers[rdata.preference].append(rdata.exchange)
            preferences = mxers.keys()
            preferences.sort()
            for p in preferences:
                for mxer in mxers[p]:
                    mx_line = "MX (%s) = " % p
                    print mx_line, mxer
                    mx_a = _cache_result(mxer, 'A')
                    if mx_a:
                        for rdata in mx_a:
                            print ' '*len(mx_line), "%s (%s)" % (rdata.address, _cache_result(rdata.address))
                    else:
                        print "NO A RECORD FOR THIS MAIL EXCHANGE"
        else:
            print "NO MX RECORDS"

        print

        if txt:
            for rdata in txt:
                print "TXT =", rdata.strings
        else:
            print "NO TXT RECORDS"

        print

