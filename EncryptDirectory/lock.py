#!/usr/bin/python2
import binascii
from Crypto.Cipher import AES
from binascii import *
import sys
import os
import random
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

def padding(inputfile):
    # inputdata = open(inputfile)
    textblock = []
    flag = 0
    index = 0
    while index < len(inputfile):
        if index + 16 > len(inputfile):
            textblock.append(inputfile[index:])
            flag = 1
            break
        if index + 16 == len(inputfile):
            textblock.append(inputfile[index:])
            break
        # print inputfile[index:16]
        textblock.append(inputfile[index: index + 16])
        index += 16
    
    if flag == 1:
        numtopad = 16 - len(textblock[-1])
        lastblock = textblock[-1]
        padding = ""
        for _ in xrange(numtopad):
            padding += str("0"+hex(numtopad)[-1])
        lastblock += padding.decode("hex")
        textblock[-1] = lastblock
    else:
        lastblock = "10101010101010101010101010101010".decode("hex")
        textblock.append(lastblock)
    
    paddedstring = ""
    for block in textblock:
        paddedstring += block
    return paddedstring

def Xoring(a,b):
    c=int(a,16)^int(b,16)
    c=format(c, '#034x')[2:]
    return c

def ECBencrypt(key, raw):
    if (raw is None) or (len(raw) == 0):
        raise ValueError('input text cannot be null or empty set')
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    ciphertext = cipher.encrypt(raw)
    return binascii.hexlify(bytearray(ciphertext)).decode('utf-8')

def CBC_ENC(inputF,IV,k,BS):
    ct=''
    msg_pad = padding(inputF)
    for i in range(0,len(msg_pad)/BS):
        msg_blocksize=hexlify(msg_pad[BS*i:BS*(i+1)])
        d=unhexlify(Xoring(msg_blocksize,IV))
        ci=ECBencrypt(k,d)
        ct= ct+ci
        IV=ci
    return ct

def CBC_Mac(inputF,IV,k,BS):
    ct=''
    msg_pad = padding(inputF)
    for i in range(0,len(msg_pad)/BS):
        msg_blocksize=hexlify(msg_pad[BS*i:BS*(i+1)])
        d=unhexlify(Xoring(msg_blocksize,IV))
        ci=ECBencrypt(k,d)
        IV=ci
    return ci

def rsaEncryption(M, e, N,n):
    lr=random.getrandbits(N/2 -2)
    strM=bin(int(M))[2:]
    while len(strM) < N/2:
        strM = "0"*(N/2 - len(strM)) + strM
    
    strR=bin(lr)[2:]
    while len(strR)!= N/2 - 2:
        lr=random.getrandbits(N/2-2)
        strR=bin(lr)[2:]
    
    padM=int(strR+strM,2)
    # RSA C = M^e mod n
    return fastExpMod(padM, e, n)

def rsa_validate(M, e,n):
    return fastExpMod(M, e, n)

def rsa_sign(M, e,n):
    
    return fastExpMod(M, e, n)

if __name__ == "__main__":
    
    f_pubkey= open(sys.argv[(sys.argv.index("-p") + 1)],'r')
    pubKEY=f_pubkey.read()
    f_seckey = open(sys.argv[(sys.argv.index("-r") + 1)], 'r')
    secKEY = f_seckey.read().strip()
    f_vkkey = open(sys.argv[(sys.argv.index("-vk") + 1)], 'r')
    vkPubKEY = f_vkkey.read().split()
    f_input = sys.argv[(sys.argv.index("-d") + 1)]
    inputFile=f_input
    
    # 1.verify the integrity of the unlocking party's publik key
    unlockPubKeyHash=hashlib.sha256(pubKEY).hexdigest()
    verifyPubKeySig=open(sys.argv[(sys.argv.index("-p") + 1)]+"-casig",'r').read().strip()
    
    verifyPubKey=rsa_validate(int(verifyPubKeySig),int(vkPubKEY[2]),int(vkPubKEY[1]))
    
    if(verifyPubKey==int(unlockPubKeyHash,16)):
        print "validated integrity"
    else:
        print "invalidated integrity"

    # 2.1 generate the aes key
    aesKey=os.urandom(32).encode("hex")
    # 2.1 enc this key
    pub=pubKEY.split()
    encAesKey=rsaEncryption(int(aesKey,16),int(pub[2]),int(pub[0]),int(pub[1]))

    keyManifest=open("keyManifest", "w")
    keyManifest.write(str(encAesKey))
    keyManifest.close()

    
    # 3.sign the symmetric key manifest
    aeskeyM=open("keyManifest").read().strip()
    hashAesKeyM=hashlib.sha256(aeskeyM).hexdigest()
    sigAesKey=rsa_sign(int(hashAesKeyM,16),int(secKEY[2]),int(secKEY[1]))

    sigkey=open("sigkey","w")
    sigkey.write(str(sigAesKey))
    sigkey.close()

    # 4.encrypt cbc
    file=os.listdir(inputFile)
    for i in range (0,len(file)):
        BS = AES.block_size
        if "iv" in sys.argv:
            f_IV = open(sys.argv[(sys.argv.index("-v") + 1)], 'r')
            IV = f_IV.read()
        else:
            IV = os.urandom(16).encode("hex")
        enc=CBC_ENC(open(f_input+"/"+file[i]).read(),IV,aesKey,BS)
        cipher=IV+enc
        newfile = open(f_input+"/"+file[i]+"-cipher", "w")
        newfile.write(cipher)
        newfile.close()

        # 5. generate the tag
        
        iv='00000000000000000000000000000000'
        tag=CBC_Mac(open(f_input+"/"+file[i]+"-cipher").read(),iv,aesKey,BS)
        newfiletag = open(f_input+"/"+file[i] + "-cipher-tag", "w")
        newfiletag.write(tag)
    os.remove(f_input+"/"+file[i])



    f_pubkey.close()
    f_seckey.close()
    f_vkkey.close()
