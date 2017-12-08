#!/usr/bin/python2
import sys
import random
import math
import hashlib
def fastExpMod(b, e, m):
    """
    e = e0*(2^0) + e1*(2^1) + e2*(2^2) + ... + en * (2^n)

    b^e = b^(e0*(2^0) + e1*(2^1) + e2*(2^2) + ... + en * (2^n))
        = b^(e0*(2^0)) * b^(e1*(2^1)) * b^(e2*(2^2)) * ... * b^(en*(2^n))

    b^e mod m = ((b^(e0*(2^0)) mod m) * (b^(e1*(2^1)) mod m) * (b^(e2*(2^2)) mod m) * ... * (b^(en*(2^n)) mod m) mod m
    """
    result = 1
    while e != 0:
        if (e&1) == 1:
            # ei = 1, then mul
            result = (result * b) % m
        e >>= 1
        # b, b^2, b^4, b^8, ... , b^(2^n)
        b = (b*b) % m
    return result

#M=message, e=private key, n=p*q
def rsa_sign(M, e,n):

    return fastExpMod(M, e, n)

if   __name__ == "__main__":
    #hash with the file message
    f_input=open(sys.argv[(sys.argv.index("-m")+1)],'r')
    message=f_input.read().strip()
    input_hash= hashlib.sha256(message).hexdigest()

    f_key=open(sys.argv[(sys.argv.index("-k")+1)],'r')
    key=f_key.read().split()

    signature = rsa_sign(int(input_hash,16), int(key[2]), int(key[1]))
    sig=str(signature)
    f_output=open(sys.argv[(sys.argv.index("-s")+1)],'w')
    output = f_output.write(sig)

    f_output.close()
    f_input.close()
    f_key.close()




