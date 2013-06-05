'''
Created on 2011-11-5

@author: vedopar
'''
import string,random,hashlib,binascii
from pyDes import *

'''for 56-bit string key to 64-bit binary key generation'''
def genkey(input):
    if len(input) != 7:
        print "input for key is wrong"
        return 0
    bits=""
    for i in input:
        bits=bits+bin(ord(i))[2:].ljust(8,'0')
    key=""
    for i in range(8):
        key=key+'0'+bits[i*7:i*7+7]
    return btos(key)

'''to transfer binary array to string data'''
def btos(barray):
    darray=""
    for i in range(8):
        bit=0
        for j in range(8):
            temp=string.atoi(barray[i*8+j])
            bit=bit*2+temp
        darray=darray+chr(bit)
    return darray

'''main course of LM'''
def LMhash():
    yanzheng=0
    tianchong='\0'
    data="KGS!@#$%"
    raw_message=""
    while yanzheng is 0:
        raw_message=raw_input("This is LM hash.\nyour password:")
        if len(raw_message) > 14:
            print "the password is out of range"
        elif len(raw_message) is 0:
            print "please input your password"
        else:
            yanzheng=1
            
    message=""
    
    for i in raw_message:
        message=message+i.upper()
        
    for i in range(14-len(raw_message)):
        message=message+tianchong
        
    key1=genkey(message[:7])
    key2=genkey(message[7:])
    
    k1 = des(key1, ECB, pad=None)
    k2= des(key2, ECB, pad=None)
    d1 = k1.encrypt(data)
    d2 = k2.encrypt(data)
    return d1+d2

'''main course of NT hash generation'''
def NThash():
    yanzheng=0
    raw_password=""
    
    while yanzheng is 0:
        raw_password=raw_input("This is NT-hash.\nyour password:")
        if len(raw_password) is 0:
            print "please input your password"
        else:
            yanzheng=1
            
    password=""
    for i in raw_password:
        password=password+str(ord(i))+"00"
    mdhash=hashlib.new('md4',password).digest()
    return mdhash
    
'''main course of NTLMv1, needs LM hash value and NT hash value'''
def NTLMv1(lmh,nth):
    challenge=""
    print "\nThis is generation of response of the NTLMv1 verification"
    
    challenge=''.join(random.choice(string.letters) for i in xrange(8))
    print "\nThe random challenge:"+binascii.hexlify(challenge)
    exten1=lmh+"00000"
    k1=des(genkey(exten1[:7]),ECB,pad=None)
    k2=des(genkey(exten1[7:14]),ECB,pad=None)
    k3=des(genkey(exten1[14:]),ECB,pad=None)
    response1=k1.encrypt(challenge)+k2.encrypt(challenge)+k3.encrypt(challenge)
    
    exten2=nth+"00000"
    k1=des(genkey(exten2[:7]),ECB,pad=None)
    k2=des(genkey(exten2[7:14]),ECB,pad=None)
    k3=des(genkey(exten2[14:]),ECB,pad=None)
    response2=k1.encrypt(challenge)+k2.encrypt(challenge)+k3.encrypt(challenge)
    
    print "\nresponse1:"+binascii.hexlify(response1)
    print "\nresponse2:"+binascii.hexlify(response2)

if __name__ == '__main__':
    lmh=LMhash()
    nth=NThash()
    print "\nThe LM hash value:"+binascii.hexlify(lmh)
    print "\nThe NT-hash value:"+binascii.hexlify(nth)
    NTLMv1(lmh,nth)
