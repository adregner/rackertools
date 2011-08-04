
import dns.resolver

def run(args):
    for domain in args:
        print '------------', domain, '------------'

        try:
            for rdata in dns.resolver.query(domain, 'NS'):
                print "NS =", rdata.target
        except dns.resolver.NoAnswer:
            print "NO NS RECORD"

        print

        try:
            for rdata in dns.resolver.query(domain, 'A'):
                print "A =", rdata.address
        except dns.resolver.NoAnswer:
            print "NO A RECORD"

        print

        try:
            mxers = {}
            for rdata in dns.resolver.query(domain, 'MX'):
                if rdata.preference not in mxers:
                    mxers[rdata.preference] = []
                mxers[rdata.preference].append(rdata.exchange)
            preferences = mxers.keys()
            preferences.sort()
            for p in preferences:
                for mxer in mxers[p]:
                    print "MX (%s) = " % p, mxer
        except dns.resolver.NoAnswer:
            print "NO MX RECORDS"

        print

        try:
            for rdata in dns.resolver.query(domain, 'TXT'):
                print "TXT =", rdata.strings
        except dns.resolver.NoAnswer:
            print "NO TXT RECORDS"

        print

