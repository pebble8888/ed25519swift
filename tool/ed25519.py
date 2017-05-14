import hashlib

b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

def H(m):
  return hashlib.sha512(m).digest()

def expmod(b,e,m):
  if e == 0: return 1
  t = expmod(b,e/2,m)**2 % m
  if e & 1: t = (t*b) % m
  return t

def inv(x):
  return expmod(x,q-2,q)

d = -121665 * inv(121666)
I = expmod(2,(q-1)/4,q)

def xrecover(y):
  xx = (y*y-1) * inv(d*y*y+1)
  print "xx:"
  print xx
  x = expmod(xx,(q+3)/8,q)
  print "x1:"
  print x
  #print "I:"
  #print I
  print "q:"
  print q

  #print "x*x:"
  #print x*x
  print "(x*x - xx) % q : "
  print (x*x - xx) % q

  if ((x*x - xx) % q) != 0:
    x = (x*I) % q
    print "x2:"
    print x

  if x % 2 != 0:
    x = q-x

  print "x3:"
  print x
  return x

By = 4 * inv(5)
Bx = xrecover(By)
B = [Bx % q,By % q]

def edwards(P,Q):
  x1 = P[0]
  y1 = P[1]
  x2 = Q[0]
  y2 = Q[1]
  x3 = (x1*y2+x2*y1) * inv(1+d*x1*x2*y1*y2)
  y3 = (y1*y2+x1*x2) * inv(1-d*x1*x2*y1*y2)
  return [x3 % q,y3 % q]

def scalarmult(P,e):
  if e == 0: return [0,1]
  Q = scalarmult(P,e/2)
  Q = edwards(Q,Q)
  if e & 1: Q = edwards(Q,P)
  return Q

def encodeint(y):
  bits = [(y >> i) & 1 for i in range(b)]
  return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b/8)])

# arg: string
def encodepoint(P):
  x = P[0]
  y = P[1]
  bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
  return ''.join([chr(sum([bits[i * 8 + j] << j for j in range(8)])) for i in range(b/8)])

def bit(h,i):
  return (ord(h[i/8]) >> (i%8)) & 1

#
def publickey(sk):
  h = H(sk)
  #print "h:"
  #print h.encode("hex")
  a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
  print "a:"
  print a
  print "By:"
  print By
  print "Bx:"
  print Bx
  print "Bx % q:"
  print Bx % q
  print "B:"
  print B
  A = scalarmult(B,a)
  print "A:"
  print A
  return encodepoint(A)

# -> BigUInt
def Hint(m):
  h = H(m)
  return sum(2**i * bit(h,i) for i in range(2*b))

def signature(m,sk,pk):
  h = H(sk)
  a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
  r = Hint(''.join([h[i] for i in range(b/8,b/4)]) + m)
  R = scalarmult(B,r)
  S = (r + Hint(encodepoint(R) + pk + m) * a) % l
  return encodepoint(R) + encodeint(S)

# 
def isoncurve(P):
  x = P[0]
  y = P[1]
  return (-x*x + y*y - 1 - d*x*x*y*y) % q == 0

def decodeint(s):
  return sum(2**i * bit(s,i) for i in range(0,b))

def decodepoint(s):
  y = sum(2**i * bit(s,i) for i in range(0,b-1))
  x = xrecover(y)
  if x & 1 != bit(s,b-1): x = q-x
  P = [x,y]
  if not isoncurve(P): raise Exception("decoding point that is not on curve")
  return P

def checkvalid(s,m,pk):
  if len(s) != b/4: raise Exception("signature length is wrong")
  if len(pk) != b/8: raise Exception("public-key length is wrong")

  #D1 = d
  #print "D1:"
  #print D1

  #E1 = expmod(123, 456, 789)
  #print "E1:"
  #print E1

  #E2 = inv(-63071608575235754152816114216420641339846018691767810910708400832114223588254292410448319)
  #print "E2:"
  #print E2

  EE = edwards([123,456], [789, 12])
  # ok
  print "EE:"
  print EE

  R = decodepoint(s[0:b/8])
  #print "R:"
  #print R
  A = decodepoint(pk)
  #print "A:"
  #print A
  S = decodeint(s[b/8:b/4])
  #print "S:"
  #print S
  h = Hint(encodepoint(R) + pk + m)
  #print "h:"
  #print h
  if scalarmult(B,S) != edwards(R,scalarmult(A,h)):
    raise Exception("signature does not pass verification")
