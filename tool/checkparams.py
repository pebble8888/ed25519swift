#!/usr/bin/env python2

import ed25519
import sys
import binascii

#assert b >= 10
#assert 8 * len(H("hash input")) == 2 * b
#assert expmod(2,q-1,q) == 1
#assert q % 4 == 1
#assert expmod(2,l-1,l) == 1
#assert l >= 2**(b-4)
#assert l <= 2**(b-3)
#assert expmod(d,(q-1)/2,q) == q-1
#assert expmod(I,2,q) == q-1
#assert isoncurve(B)
#assert scalarmult(B,l) == [0,1]

#bytes_data = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
#1A = decodepoint(bytes_data)
#print A
#a = encodepoint(A)
#print "a:" + binascii.b2a_hex(a)
sk = b'\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60'
print "sk:" + binascii.b2a_hex(sk)
pk = ed25519.publickey(sk)
print "pk:" + binascii.hexlify(pk) 
#d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
#:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
#::
m = ''
#e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b:

s = ed25519.signature(m,sk,pk)
print "s:" + binascii.hexlify(s)
ed25519.checkvalid(s,m,pk)
