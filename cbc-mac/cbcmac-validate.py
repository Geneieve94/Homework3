#!/usr/bin/python2
import binascii
from Crypto.Cipher import AES
from binascii import *
from Crypto import Random
import sys
import os
#padding generation



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



def CBC_MacValidate(inputF,IV,k,BS):
    ct=''
    msg_pad = padding(inputF)
    for i in range(0,len(msg_pad)/BS):
        msg_blocksize=hexlify(msg_pad[BS*i:BS*(i+1)])
        d=unhexlify(Xoring(msg_blocksize,IV))
        ci=ECBencrypt(k,d)
        ct= ct+ci
        IV=ci
    return ci

if __name__ == "__main__":

    f_key= open(sys.argv[(sys.argv.index("-k") + 1)],'r')
    KEY=f_key.read()
    f_input = open(sys.argv[(sys.argv.index("-m") + 1)], 'r' )
    inputFile=f_input.read()

    IV ='00000000000000000000000000000000'
    BS = AES.block_size

    cipher=CBC_MacValidate(inputFile,IV,KEY,BS)
    validate_m = str(len(inputFile)) + cipher
    validate_t = str(len(inputFile)) + cipher

    f_validate= open(sys.argv[(sys.argv.index("-t") + 1)],'r')
    if (validate_m==validate_t):
        print "this is a successful cbcmac-tag"
    else:
        print "fail!"

