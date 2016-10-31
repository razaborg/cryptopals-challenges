#!/usr/bin/env python3

import base64
import binascii
import string
import itertools
import sys
from Crypto.Cipher import AES
from Crypto import Random


def hex2b64(hex_data):
    #hex_data = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    txt_data = binascii.unhexlify(hex_data)
    b64_data = base64.b64encode(txt_data)
    return b64_data


##############################################################################
# fixedXOR réalise l'opération XOR entre a et b de même taille
# - a: format byte en HEXADECIMAL
# - b: format byte en HEXADECIMAL
# Retourne le résultat du XOR dans un byte en hexa
##############################################################################
def fixedXOR(a,b):
    #a et b doivent être des valeurs en hexa de même taille
    assert(isinstance(a, bytes))
    assert(isinstance(b, bytes))
    assert(len(a) == len(b))

    a = binascii.unhexlify(a)
    b = binascii.unhexlify(b)

    # pour les besoins du XOR on convertit tout ça en int
    int_a = int.from_bytes(a, byteorder='big')
    int_b = int.from_bytes(b, byteorder='big')

    # on fait un XOR entre les int
    out = int_a ^ int_b

    # on convertir tout ça en hexa
    out = out.to_bytes(out.bit_length() // 8 + 1, byteorder='big')
    out = binascii.hexlify(out)

    return(out)




##############################################################################
# unXOR permet de bruteforcer une chaine a qui a été XORé avec un seul caractère
# - a est une chaine de type byte et codé en hexadécimal
# Retourne un dictionnaire contenant {clef:message décodé}
##############################################################################
def unXOR(a):
    assert(isinstance(a, bytes))

    # Création d'une liste contenant l'ensemble des lettres de l'alhpabet ASCII
    alphabet = list(string.printable)

    # On recupere la longueur de a
    lena = len(binascii.unhexlify(a))

    bestCandidate = {'key': '', 'score': 0, 'solution':''}

    # Pour chaque lettre de notre alphabet
    for letter in alphabet:
        # on va faire en sorte qu'elle fasse la même taille que a
        key = bytes(letter * lena, 'utf-8')
        # et on converti cette magnifique chose en hexa
        key=binascii.hexlify(key)

        # on envoie donc notre clef toute neuve ainsi que a à la fonction fixedXOR
        out = fixedXOR(a, key)
        # on dés-hex tout ça
        try :
            out = binascii.unhexlify(out)
        except:
            continue

        #ensuite on va maintenant tester out afin de verifier que ce soit de l'anglais
        s=0
        # print(out)
        # input()
        # Pour chaque caracteres de la chaine "ETAOIN SHRDLU"
        for l in "ETAOIN SHRDLU":
            count = str(out).count(l) # on compte les majucules
            count = count + str(out).count(l.lower()) # puis les minuscules
            s+=count/len(out) # on calcule un rapport à la taille de la chaine

        # et a chaque fois on compare, voir si on avait déjà une chaine avec un meilleur score
        if s > bestCandidate['score']:
            bestCandidate = {'key': letter, 'score': s, 'solution':out}
        # print(letter, s, out)
        # input()
    # a la fin on retourne le best of the bests
    return(bestCandidate)

def testXORinfile(filename):
    f = open(filename, 'rb')
    out = {'key': '', 'score': 0, 'solution':''}
    for line in f:
        # On décode la ligne pour pouvoir la traiter comme une string
        line = line.decode('utf-8')
        # On vire le \n à la fin
        line = line.replace('\n', '')
        # On retransforme en byte
        line = line.encode('utf-8')

        # on compare pour voir si on avait déjà une meilleure candidate ou pas
        if out['score'] < unXOR(line)['score']:
            out = unXOR(line)

    # on recupere le best of the best
    return(out)


##############################################################################
# repeatingKeyXOR permet de réaliser un l'opération XOR entre 2 chaines de taille différente
# Cette fonction opère en ralongeant bKey à la taille de bIn
# - bIn est une chaine de type byte et codé en hexadécimal
# - bKey est une chaine de type byte et codé en hexadécimal
# Retourne la solution sous forme de byte codé en hexadécmial
##############################################################################
def repeatingKeyXOR(bIn, bKey):
    # On check que bIn et bKey soient bien des "instances de la classe bytes"
    # EN rgos on vérifie qu'ils soient de type byte.
    assert(isinstance(bIn, bytes))
    assert(isinstance(bKey, bytes))

    in_str = binascii.unhexlify(bIn)
    key_str = binascii.unhexlify(bKey)
    len_in = len(in_str)
    len_key = len(key_str)

    # On fait une clef de la taille de len_in
    key_str = key_str * len_in
    # Et après on tronque key_str à la taille de len_in pour avoir *exacetement* la même taille
    key_str = key_str[:len_in]

    # On vérifie que les tailles soient bonnes
    assert(len(key_str) == len(in_str))

    # Ensuite on formate la clef en hexa et on envoie tout ça
    bRepeatedKey = binascii.hexlify(key_str)
    assert(len(bIn) == len(bRepeatedKey))

    return(fixedXOR(bIn, bRepeatedKey))

##############################################################################
# Hamming calcule la distance de Hamming entre bA et bB
# - bA est un type byte
# - bB est uun type byte
# retourne un int correspondant à la distance de hamming
##############################################################################
def hamming(bA, bB):
    assert(isinstance(bA, bytes))
    assert(isinstance(bB, bytes))
    assert(len(bA) == len(bB))
    c = 0
    for byte_a, byte_b in zip(bA, bB):
        # print(bin(byte_a), bin(byte_b), bin(byte_a ^ byte_b).count('1'))

        # On fait un XOR octet à octet (byte to byte)
        # Et on compte les bits à 1 en sortie de ce XOR
        # Cela correspond au nombre de changements à opérér pour passer de byte_a à byte_b
        c += bin(byte_a ^ byte_b).count('1')
        # Le compteur additionne ce nombre de changements pour chaque octets de bA et de bB

    return c # et à la fin on renvoie le résultat total

##############################################################################
# readb64File ouvre le fichier 'infile' et récupère tout son contenu puis le décode en b64
# - infile est un nom de fichier
# retourne un type byte contenant le résultat du décodage
##############################################################################
def readb64File(infile):
    # on ouvre le fichier en base64
    f = open(infile, 'r')
    # on met tout son contenu dans une liste
    out = b''
    for line in f:
        # on vire les \n
        line = line.replace('\n', '')
        # on rajoute ça dans out sans oublier de transformer notre line en type byte
        out += line.encode()
    # out contient maintenant un byte avec du contenu en b64

    out = base64.b64decode(out)
    # for byte in out:
    #     print(byte)
    # print(out)
    return out

def findKeysize(rawbyte, mini=2, maxi=40):
    result = {'keysize': 0, 'hamming': 100}
    for KEYSIZE in range(mini, maxi):

        # first = b64Output[:KEYSIZE]
        # second = b64Output[KEYSIZE:KEYSIZE*2]
        # third = b64Output[KEYSIZE*2:KEYSIZE*3]
        # fourth = b64Output[KEYSIZE*3:KEYSIZE*4]

        blocks = [ rawbyte[KEYSIZE*i : KEYSIZE* (i+1)] for i in range(4) ]
        # print(i)
        # print(blocks)
        # exit()
        haming = 0
        haming += hamming(blocks[0], blocks[1])
        haming += hamming(blocks[0], blocks[2])
        haming += hamming(blocks[0], blocks[3])
        haming += hamming(blocks[1], blocks[2])
        haming += hamming(blocks[1], blocks[3])
        haming += hamming(blocks[2], blocks[3])

        # normalizedHamming = hamming(first, second)/KEYSIZE
        normalizedHamming = haming/KEYSIZE
        if normalizedHamming < result['hamming']:
            result['hamming'] = normalizedHamming
            result['keysize'] = KEYSIZE
        # print(KEYSIZE, normalizedHamming)
    # exit()
    return(result['keysize'])

def divideBytesInBlocks(bytes_In, blocksSize):
    assert(isinstance(bytes_In, bytes))
    assert(isinstance(blocksSize, int))

    # On construit une liste de taille rangeSize qui va contenir des blocks de taille blocksSize
    # rangeSIze correspond à la longueur totale de bytes_In divisée par des blocks de taille blocksSize.
    # comme cette division peut donner un chiffre non entier, on l'arrondie et on y ajoute le reste de la division
    # ainsi cela donnera la taille exacte qu'il nous faut
    rangeSize = int(len(bytes_In)/blocksSize) + len(bytes_In)%blocksSize
    # construction des blocks
    blocks = [bytes_In[blocksSize*i : blocksSize* (i+1)] for i in range(rangeSize)]

    # vecteur de test pour vérifier que si on assemble nos blocks on récupère bien qqch qui est égal à bytes_In
    test =b''
    for i in range(len(blocks)):
        test += blocks[i]
    assert(test == bytes_In)

    return(blocks)

def sizeBlocks2bytesBlocks(blocks):
    assert(isinstance(blocks, list))
    blocksLen = len(blocks[0])
    nBlocks = len(blocks)

    # print("on a ", nBlocks, " blocks de taille", blocksLen)
    # On crée une liste contenant autant de champ que la la taille de chaque block
    outList = [b'']*blocksLen

    # pour chaque octet(n°i) de chaque block
    for byte_i in range(blocksLen):
        # pour chaque block n°n de la liste blocks
        for block_n in range(nBlocks):
            # On verifie qu'on a bien la taille de block que l'on est sensé avoir
            if len(blocks[block_n]) == blocksLen:
                outList[byte_i] += bytes([blocks[block_n][byte_i]])
                # print(blocks[block_n])
            else:
                # Et si on a une taille de bloc cheloue
                # Alors on verifie que l'on essaie pas de choper un octet qui n'existe pas dans ce bloc
                if byte_i < len(blocks[block_n]):
                    outList[byte_i] += bytes([blocks[block_n][byte_i]])
    return(outList)

def decryptAES(bData, bKey):
    assert(isinstance(bData, bytes))
    assert(isinstance(bKey, bytes))


    #key long: 16 (AES-128), 24 (AES-192), or 32 (AES-256)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(bKey, AES.MODE_ECB, iv)
    msg = cipher.decrypt(bData)
    # msg = iv + cipher.encrypt(b'Attack at dawn')
    return(msg)

def readFileHex(infile):
    f = open(infile, 'rb')
    data = []
    for line in f:
        data.append(line[:-1])

    return(data)
