
import re
import sys

sys.path.append('vendor/')

import dns.resolver
import dns.reversename
from whois import NICClient

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

def _get_ptr(ip_address):
    reverse = _clean_query(dns.reversename.from_address(ip_address), 'PTR')
    ptr = reverse[0].target if reverse else "NO PTR RECORD"
    return ptr

def _get_isp(ip_address, nic_client):
    isps = {}
    whois_response = nic_client.whois_lookup({}, "n %s"%ip_address, NICClient.WHOIS_RECURSE)
    for line in whois_response.split("\n"):
        m = re.search('(.+) \((NET-[0-9-]+)\)', line)
        if m:
            isps[m.group(2)] = m.group(1)
    nets = isps.keys()
    nets.sort()
    return isps[nets[-1]]

def run(args):
    nic_client = NICClient()
    
    for domain in args:
        print '------------', domain, '------------'
        
        ns = _clean_query(domain, 'NS')
        a = _clean_query(domain, 'A')
        mx = _clean_query(domain, 'MX')
        txt = _clean_query(domain, 'TXT')

        if ns:
            for rdata in ns:
                print "NS =", rdata.target
        else:
            print "NO NS RECORD"

        print

        if a:
            for rdata in a:
                print "A = %s (%s)" % (rdata.address, _get_ptr(rdata.address))
                print "    %s" % _get_isp(rdata.address, nic_client)
        else:
            print "NO A RECORD"

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
                    mx_a = _clean_query(mxer, 'A')
                    if mx_a:
                        for rdata in mx_a:
                            print ' '*len(mx_line), "%s (%s)" % (rdata.address, _get_ptr(rdata.address))
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

