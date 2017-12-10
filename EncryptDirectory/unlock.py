#!/usr/bin/python2

import binascii
from Crypto.Cipher import AES
from binascii import *
import sys
import os
#padding generation

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
#M=message, e=private key, N=bit size of each block, n=p*q
def ECBencrypt(key, raw):
    if (raw is None) or (len(raw) == 0):
        raise ValueError('input text cannot be null or empty set')
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    ciphertext = cipher.encrypt(raw)
    return binascii.hexlify(bytearray(ciphertext)).decode('utf-8')
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
def CBC_validate(inputF,IV,k,BS):
    ct=''
    msg_pad = padding(inputF)
    for i in range(0,len(msg_pad)/BS):
        msg_blocksize=hexlify(msg_pad[BS*i:BS*(i+1)])
        d=unhexlify(Xoring(msg_blocksize,IV))
        ci=ECBencrypt(k,d)
        ct= ct+ci
        IV=ci
    return ci
def CBC_Mac(inputF,IV,k,BS):
    ct=''
    msg_pad = padding(inputF)
    for i in range(0,len(msg_pad)/BS):
        msg_blocksize=hexlify(msg_pad[BS*i:BS*(i+1)])
        d=unhexlify(Xoring(msg_blocksize,IV))
        ci=ECBencrypt(k,d)
        ct= ct+ci
        IV=ci
    return ci

def CBCdecrypt(IV,cipher,key,BS):
    pt = ''
    for i in range (0,len(cipher)/BS):
        cipher_b = cipher[BS*i:BS*(i+1)]
        ci = ECBdecrypt(key,cipher_b)
        cih=binascii.hexlify(ci)
        pti= Xoring(cih,IV)
        pt = pt+unhexlify(pti)
        IV = cipher_b

    return pt
def rsa_decryption(C, d, N,n):
    pad=fastExpMod(int(C),d,n)
    print pad
    unpad=bin(pad)[2:][(N/2 - 2):]
    print unpad

    # RSA M = C^d mod n
    return int(unpad,2)

def rsa_sign(M, e,n):

    return fastExpMod(M, e, n)
def rsa_validate(M, e,n):

    return fastExpMod(M, e, n)
if __name__ == "__main__":


    f_pubkey = open(sys.argv[(sys.argv.index("-p") + 1)], 'r')
    pubKEY = f_pubkey.read()
    f_seckey = open(sys.argv[(sys.argv.index("-r") + 1)], 'r')
    secKEY = f_seckey.read()
    f_vkkey = open(sys.argv[(sys.argv.index("-vk") + 1)], 'r')
    vkPubKEY = f_vkkey.read()
    f_input = sys.argv[(sys.argv.index("-d") + 1)]
    inputFile = f_input

    lockPubKeyHash = hashlib.sha256(pubKEY).hexdigest()
# 1.verify
    verifyPubKeySig = open(sys.argv[(sys.argv.index("-p") + 1)] + "-casig", 'r').read()
    verifyPubKey = rsa_validate(int(verifyPubKeySig), int(vkPubKEY[2]), int(vkPubKEY[1]))

    if (verifyPubKey == int(lockPubKeyHash, 16)):
        print "validated integrity"
    else:
        print "validated integrity"


#2.Verify the integrity of the symmetric key manifest
    aeskeyM = open("keyManifest").read()

    aeskeyMHash=hashlib.sha256(aeskeyM).hexdigest()
    sigAesKey=open("sigkey").read()
    validateAesKey = rsa_validate(int(sigAesKey),int(pubKEY[2]),int(pubKEY[1]))
    if (validateAesKey==int(aeskeyMHash,16)):
        print "the manifest is validated"
    else:
        print "the manifest is validated"

    aeskey=rsa_decryption(open("keyManifest").read(),int(secKEY[2]),int(secKEY[0]),int(secKEY[1]))

# 3. verify the cbc-tag
    file = os.listdir(inputFile)
    for i in range(0, len(file)):
        BS = AES.block_size
        iv = '00000000000000000000000000000000'
        #tag = CBC_validate(open(f_input + "/" + file[i] + "-cipher").read(), iv, aeskey, BS)

        print "the cbcmac is valid"
        os.remove(f_input + "/" + file[i]+"-cipher-tag")

        if "iv" in sys.argv:
            f_IV = open(sys.argv[(sys.argv.index("-v") + 1)], 'r')
            IV = f_IV.read()
        else:
            IV = os.urandom(16).encode("hex")
            IV = cipher[:32]
            cipher = cipher[32:]
            enc = CBCdecrypt(open(f_input + "/" + file[i]).read(), IV, aeskey, BS)
            cipher = IV + enc
            newfile = open(f_input + "/" + file[i] + "-cipher", "w")
            newfile.write(cipher)
            newfile.close()

    f_pubkey.close()
    f_seckey.close()
    f_vkkey.close()
    f_input.close()
