#!/usr/bin/env python

# Copyright (C)2012 by Jan-Piet Mens <jpmens () gmail.com>
#
# This file is part of "DV" (DNS file verification)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
#	The above copyright notice and this permission notice shall be included
#	in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.


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
        print "%s.%s. %d IN  TXT \"%s\"" % (hashfile(file), DNS_RHS, DNS_TTL, file)

