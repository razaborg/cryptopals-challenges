#!/usr/bin/env python3

from cryptopals import *
from operator import itemgetter
import itertools

def chall1():
    print(hex2b64(b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'))

def chall2():
    print(fixedXOR(b'1c0111001f010100061a024b53535009181c', b'686974207468652062756c6c277320657965'))

def chall3():
    print(testXORinfile("4.txt"))

def chall4():
    print(unXOR(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))

def chall5():
    str = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
    str = binascii.hexlify(str)
    key = b"ICE"
    key = binascii.hexlify(key)
    out = repeatingKeyXOR(str, key)
    print(out)
    assert(out == b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')

def chall6():
    assert(hamming(b'this is a test', b'wokka wokka!!!') == 37)
    # ouverture du fichier et récupération du contenu b64 décodé
    b64_file = readb64File("6.txt")
    # on déduit la taille de la clef
    keysize = findKeysize(b64_file)
    # keysize = 3
    print("Keysize:", keysize)
    # on construit des minis blocks à partir de notre taille de clef
    blocks = divideBytesInBlocks(b64_file, keysize)

    outlist = sizeBlocks2bytesBlocks(blocks)

    key = ''
    for i in range(len(outlist)):
        outlist[i] = binascii.hexlify(outlist[i])
        key += unXOR(outlist[i])['key']
    print("Key: ", key.encode())
    # exit()
    out = repeatingKeyXOR(binascii.hexlify(b64_file), binascii.hexlify(key.encode()))
    out = binascii.unhexlify(out)
    assert(len(out) == len(b64_file))
    print(out.decode())

def chall7():
    # ouverture du fichier et récupération du contenu b64 décodé
    b64_file = readb64File("7.txt")
    key = b'YELLOW SUBMARINE'
    out = decryptAES(b64_file, key)
    print(out.decode())

def chall8():
    fContent = readFileHex("8.txt")

    # candidates = {16: [], 24 : [], 32 : []}
    # alphabet = dict().fromkeys(list(string.printable))
    dict_bytes = {}
    n=0
    for hexstring, n in zip(fContent, range(len(fContent))):
        raw = binascii.unhexlify(hexstring)

        # On convertit tou ça en blocks de 16
        blocks = divideBytesInBlocks(raw, 16)

        # Et pour détecter le chiffrement AES ECB, on va chercher les blocks dupliqués
        # Pour faire ça on va simplement comparer la taille de set(blocks) et de blocks
        # set(blocks) étant l'équivalent de blocks, mais sans les duplicatas
        if(len(set(blocks)) != len(blocks)):
            print("Potential AES-CBC detected on line {0}:".format(n))
            print(hexstring)

if __name__ == '__main__':

    # chall1()
    # chall2()
    # chall3()
    # chall4()
    # chall5()
    # chall6()
    # chall7()
    chall8()
    exit()
