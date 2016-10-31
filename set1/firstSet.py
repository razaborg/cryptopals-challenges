#!/usr/bin/env python3

from cryptopals import *
from operator import itemgetter

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
    for hexstring in fContent:
        raw = binascii.unhexlify(hexstring)
        keySize = findKeysize(raw)

        # On sait que les tailles de clefs sont forcément de 16,24, ou 32
        # On crée donc une liste candidates qui va contenir seulements
        # les contenu dont la clef est de cette taille "compatible"
        if(keySize == 16 or keySize == 24 or keySize == 32):
            # candidates[keySize].append(raw)
            print(keySize)
            for byte in raw:
                dict_bytes.update({byte : raw.count(byte) } )
            s = [(k, dict_bytes[k]) for k in sorted(dict_bytes, key=dict_bytes.get, reverse=True)]
            for k, v in s:
                print(k, v)
            input()

    # # On va traiter nos candidats par groupe de taille
    # for KEYSIZE in candidates:
    #     # pour chaque chaine candidate de taille KEYSIZE
    #     for content in candidates[KEYSIZE]:
    #         # On va saucisonner en blocs de taille KEYSIZE
    #         blocks = divideBytesInBlocks(raw, KEYSIZE)
    #         # print(len(blocks[0]))
    #         # exit()
    #         # Maintenant qu'on a des blocs qui font la taille de la clef, on va les étudier
    #         # C'est à dire que l'on va faire une étude statistique sur les bytes qui reviennt le plus souvent
    #         for i in blocks:
    #             for byte in blocks:
    #                 blocks[i].count(byte)



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
