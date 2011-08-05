
import dns.resolver
import dns.reversename

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

def run(args):
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

