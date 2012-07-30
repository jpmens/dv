#!/usr/bin/env python

import sys
from hashlib import sha1

DNS_RHS = "file.hes.jpmens.org"
DNS_TTL = 86400

def githash(data):
    s = sha1()
    s.update("blob %u\0" % len(data))
    s.update(data)
    return s.hexdigest()

def hashfile(filename):
    try:
        f = open(filename, "rb")
    except:
        print "Can't open %s" % filename
        sys.exit(2)

    sha1 = githash(f.read())
    f.close()
    return sha1

if __name__ == "__main__":

    for file in sys.argv[1:]:
        print "%s.%s %d IN  TXT \"%s\"" % (hashfile(file), DNS_RHS, DNS_TTL, file)

