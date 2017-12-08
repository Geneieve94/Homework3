#!/usr/bin/python2
import random
import sys
import hashlib

def fastExpMod(b, e, m):
    result = 1
    while e != 0:
        if (e&1) == 1:
            # e&1 means that whether e is 1 or not
            result = (result * b) % m
        e >>= 1  # e = e/2
        b = (b*b) % m
    return result
def factorize(m):
    s=0
    d=0
    reminder=m%2
    while(reminder == 0):
        s=s+1
        m=m/2
        reminder = m%2
    d=m
    return s,d
def Miller_Rabin(n):
    s, d = factorize(n - 1)
    a = random.randint(1, n-1)
    # If a^q mod n= 1, n maybe is a prime number
    if fastExpMod(a, d, n) == 1:
        return "inconclusive"
    # If there exists j satisfy a ^ ((2 ^ j) * q) mod n == n-1, n maybe is a prime number
    for j in range(0, s):
        if fastExpMod(a, (2**j)*d, n) == n - 1:
            return "inconclusive"
    # a is not a prime number
    return "composite"
def findPrime(halfkeyLength):
    while True:
        # Select a random number n
        n = random.randint(0, 1<<halfkeyLength)
        if n % 2 != 0:
            found = True
            # If n satisfy primeTest 10 times, then n should be a prime number
            for i in range(0, 10):
                if Miller_Rabin(n) == "composite":
                    found = False
                    break
            if found:
                return n
def extendedGCD(a, b):
    #a*xi + b*yi = ri
    if b == 0:
        return (1, 0, a)
    #a*x1 + b*y1 = a
    else:
        x, y, q = extendedGCD(b, a % b)  # q = GCD(a, b) = GCD(b, a%b)
        x, y = y, (x - (a // b) * y)
        return x, y, q
def selectE(fn, halfkeyLength):
    while True:
        #e and fn are relatively prime
        e = random.randint(0, 1<<halfkeyLength)
        (x, y, r) = extendedGCD(e, fn)
        if r == 1:
            return e
def computeD(fn, e):
    (x, y, r) = extendedGCD(fn, e)
    #y maybe < 0, so convert it
    if y < 0:
        return fn + y
    return y
def keyGeneration(keyLength):
    # generate public key and private key
    p = findPrime(keyLength/2)
    q = findPrime(keyLength/2)
    # find two prime number p and q
    n = p * q
    # multiply p and q to get an N
    fn = (p-1) * (q-1)
    # compute Zn*=(p-1)*(q-1)
    e = selectE(fn, keyLength/2)
    d = computeD(fn, e)
    return (len(bin(n)[2:]), n, e, d)
def rsa_sign(M, e,n):

    return fastExpMod(M, e, n)

if   __name__ == "__main__":
    n = int(sys.argv[(sys.argv.index("-n") + 1)])
    keypair = keyGeneration(n)
    publickey = str(keypair[0]) + "\n" + str(keypair[1])+"\n"+str(keypair[2])
    privatekey= str(keypair[0]) + "\n" + str(keypair[1])+"\n"+str(keypair[3])
    pk=open(sys.argv[(sys.argv.index("-p") + 1)], "w+")
    pk.write(publickey)
    prk=open(sys.argv[(sys.argv.index("-s") + 1)], "w+")
    prk.write(privatekey)
    pk.close()
    prk.close()

    input = publickey
    input_hash = hashlib.sha256(input).hexdigest()

    if "-c" in sys.argv:
        f_key = open(sys.argv[(sys.argv.index("-c") + 1)], 'r')
    else:
        f_key = open(sys.argv[(sys.argv.index("-s") + 1)], 'r')

    key = f_key.read().split()
    out = rsa_sign(int(input_hash, 16), int(key[2]), int(key[1]))
    sig = str(out)
    f_output = open(sys.argv[(sys.argv.index("-p") + 1)] + "-casig", 'w')
    output = f_output.write(sig)

    f_output.close()
    f_key.close()
