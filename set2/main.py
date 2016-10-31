#!/usr/bin/env python3

import cryptopals
from binascii import hexlify, unhexlify


def chall9():
    string = b"YELLOW SUBMARINE"
    # print(PKCS7padder(string, 20))
    assert(cryptopals.PKCS7padder(string, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04')


def chall10():
    # Just to try the cryptopals.aes_ecb() :
    mystr = b'coucou les amis!I love ricard!!!And python a bit'
    # print(mystr)
    # ciphered = cryptopals.aes_ecb(mystr, b'YELLOW SUBMARINE', 'encrypt')
    # print(ciphered)
    # print(cryptopals.aes_ecb(ciphered, b'YELLOW SUBMARINE', 'decrypt').decode())

    # Key
    key = b'YELLOW SUBMARINE'
    # Taille de block
    keysize = len(key)
    # Vecteur d'initialisation:
    iv = chr(0).encode() * keysize

    # AES CBC ENCRYPT TEST
    # On crée des blocks de 16 à partir de notre input
    blocks = cryptopals.divideBytesInBlocks(mystr, keysize)
    out = []
    # On traite les blocks un par un
    for i in range(len(blocks)):
        # Pour le premier on envoie à la fonction un XOR entre
        # iv et le premier block
        if(i == 0):
            data_in = cryptopals.fixedXOR(hexlify(iv), hexlify(blocks[i]))
        else:
            # et pour les suivants, on lui envoie les blocks n et n-1
            data_in = cryptopals.fixedXOR(hexlify(blocks[i-1]), hexlify(blocks[i]))
        data_in = unhexlify(data_in)
        out.append(data_in)
    # On a maintenant une liste
    print(out)

    # AES CBC DECRYPT TEST
    for i in range(len(blocks)

if __name__ == '__main__':
    # chall9()
    chall10()
