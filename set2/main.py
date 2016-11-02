#!/usr/bin/env python3

import cryptopals
from binascii import hexlify, unhexlify


def chall9():
    string = b"YELLOW SUBMARINE"
    # print(PKCS7padder(string, 20))
    assert(cryptopals.PKCS7padder(string, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04')


def chall10():
    # Just to try the cryptopals.aes_ecb() :
    # mystr = b'coucou les amis!I love ricard!!!And python a bit'
    # print(mystr)

    # Key
    key = b'YELLOW SUBMARINE'
    # Taille de block
    keysize = len(key)
    # Vecteur d'initialisation:
    iv = chr(0).encode() * keysize

    # en = cryptopals.aes_cbc(mystr, key, iv, 'encrypt')
    # print(en)
    # en = b''.join(en)
    # de = cryptopals.aes_cbc(en, key, iv, 'decrypt')
    # print(de)

    data = cryptopals.readb64File('10.txt')
    out = cryptopals.aes_cbc(data, key, iv, 'decrypt')
    out = b''.join(out)
    print(out.decode())



if __name__ == '__main__':
    # chall9()
    chall10()
