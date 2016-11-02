#!/usr/bin/env python3

import base64
import binascii
import string
from Crypto.Cipher import AES
from Crypto import Random


def hex2b64(hex_data):
    """Convert hex_data hexlified string into b64."""
    txt_data = binascii.unhexlify(hex_data)
    b64_data = base64.b64encode(txt_data)
    return(b64_data)


def fixedXOR(a, b, raw=0):
    """
    Do a XOR between a and b with a same size.

    :param a: The first string to XOR
    :param b: The second string to XOR
    :param raw: Boolean to either compute with raw or hexlified data
    :type a: byte
    :type b: byte
    :type raw: Boolean
    :return: The result of the xor
    :rtype: byte
    """
    # a et b doivent être des valeurs en hexa de même taille
    assert(isinstance(a, bytes))
    assert(isinstance(b, bytes))
    assert(len(a) == len(b))

    if(raw == 0):
        a = binascii.unhexlify(a)
        b = binascii.unhexlify(b)

    # pour les besoins du XOR on convertit tout ça en int
    int_a = int.from_bytes(a, byteorder='big')
    int_b = int.from_bytes(b, byteorder='big')

    # on fait un XOR entre les int
    out = int_a ^ int_b

    # on convertir tout ça en hexa
    out = out.to_bytes(out.bit_length() // 8 + 1, byteorder='big')
    if(raw == 0):
        out = binascii.hexlify(out)

    return(out)

def xor(a, b):
    """
    Do a XOR between a and b with a same size.
    Proper reviewed version of the fixedXOR(),
    with **raw inputs/outputs** (non-hexlified).

    :param a: The first byte to XOR
    :param b: The first byte to XOR
    :type a: byte
    :type b: byte
    :return: The XOR result
    :rtype: byte
    """
    assert(len(a) == len(b))

    xor = b''
    for n in range(len(a)):
        # print(a[n], b[n])
        xor += bytes([a[n] ^ b[n]])
    assert(len(a) == len(xor))

    return(xor)

def unXOR(a):
    """
    Bruteforce a string which has bin XORed with a single caracter.

    :param a: The  hexlified string to XOR
    :type a: byte
    :return: The result of the xor with the form {key:decrypted message}
    :rtype: dict
    """
    assert(isinstance(a, bytes))

    # Création d'une liste contenant l'ensemble des lettres de l'alhpabet ASCII
    alphabet = list(string.printable)

    # On recupere la longueur de a
    lena = len(binascii.unhexlify(a))

    bestCandidate = {'key': '', 'score': 0, 'solution': ''}

    # Pour chaque lettre de notre alphabet
    for letter in alphabet:
        # on va faire en sorte qu'elle fasse la même taille que a
        key = bytes(letter * lena, 'utf-8')
        # et on converti cette magnifique chose en hexa
        key = binascii.hexlify(key)

        # on envoie notre clef toute neuve ainsi que a à la fonction fixedXOR
        out = fixedXOR(a, key)
        # on dés-hex tout ça
        try:
            out = binascii.unhexlify(out)
        except:
            continue

        # ensuite on va tester out afin de verifier que ce soit de l'anglais
        s = 0
        # Pour chaque caracteres de la chaine "ETAOIN SHRDLU"
        for l in "ETAOIN SHRDLU":
            # on compte les majucules
            count = str(out).count(l)
            # puis les minuscules
            count = count + str(out).count(l.lower())
            # on calcule un rapport à la taille de la chaine
            s += count / len(out)

        # et a chaque fois on compare, voir si on avait déjà une chaine
        # avec un meilleur score
        if s > bestCandidate['score']:
            bestCandidate = {'key': letter, 'score': s, 'solution': out}
        # print(letter, s, out)
        # input()
    # a la fin on retourne le best of the bests
    return(bestCandidate)


def testXORinfile(filename):
    """
    Execute the unXOR function for each line of the input file.

    :param filename: The filename on which we'll perform the operations
    :type a: string
    :return: The line with the best score
    :rtype: string
    """
    f = open(filename, 'rb')
    out = {'key': '', 'score': 0, 'solution': ''}
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


def repeatingKeyXOR(bIn, bKey):
    """
    Do a XOR between bIn and bKey with bKey lower than bIn.
    The function simply repeat bKey until its len is equal to bIn len.

    :param bIn: The string to XOR, hexlified.
    :param bKey: The key to repeat, hexlified.
    :type bIn: byte
    :type bKey: byte
    :return: The result of the xor, hexlified.
    :rtype: byte
    """
    # On check que bIn et bKey soient bien des "instances de la classe bytes"
    # EN rgos on vérifie qu'ils soient de type byte.
    assert(isinstance(bIn, bytes))
    assert(isinstance(bKey, bytes))

    in_str = binascii.unhexlify(bIn)
    key_str = binascii.unhexlify(bKey)
    len_in = len(in_str)

    # On fait une clef de la taille de len_in
    key_str = key_str * len_in

    # Et après on tronque key_str à la taille de len_in pour avoir
    # *exactement* la même taille
    key_str = key_str[:len_in]

    # On vérifie que les tailles soient bonnes
    assert(len(key_str) == len(in_str))

    # Ensuite on formate la clef en hexa et on envoie tout ça
    bRepeatedKey = binascii.hexlify(key_str)
    assert(len(bIn) == len(bRepeatedKey))

    return(fixedXOR(bIn, bRepeatedKey))


def hamming(bA, bB):
    """
    Compute the hamming distance between bA and bB.
    bA and bB must be the same size.

    :param bA: The first byte to compare (non-hexlified)
    :param bB: The second byte to compare (non-hexlified)
    :type bA: byte
    :type bB: byte
    :return: The hamming distance between bA and bB
    :rtype: int
    """
    assert(isinstance(bA, bytes))
    assert(isinstance(bB, bytes))
    assert(len(bA) == len(bB))
    c = 0
    for byte_a, byte_b in zip(bA, bB):
        # print(bin(byte_a), bin(byte_b), bin(byte_a ^ byte_b).count('1'))

        """
        On fait un XOR octet à octet (byte to byte)
        Et on compte les bits à 1 en sortie de ce XOR
        Cela correspond au nombre de changements à opérér pour
        passer de byte_a à byte_b

        Le compteur additionne ce nombre de changements pour
        chaque octets de bA et de bB
        """
        c += bin(byte_a ^ byte_b).count('1')

    # et à la fin on renvoie le résultat total
    return c


def readb64File(infile):
    """
    Open the file 'infile' and decode its base64 content.

    :param infile: The file to read
    :type infile: string
    :return: The base64 raw decoded content
    :rtype: byte
    """
    # on ouvre le fichier en base64
    f = open(infile, 'r')
    # on met tout son contenu dans une liste
    out = b''
    for line in f:
        # on vire les \n
        line = line.replace('\n', '')
        # on rajoute ça dans out et on transforme notre line en type byte
        out += line.encode()

    return base64.b64decode(out)


def findKeysize(rawbyte, mini=2, maxi=40):
    """
    Split successively the 'rawbyte' input into blocks of sizes [mini;maxi].
    Compute the hamming distance between the 4 firsts blocks for each sizes and
    normalize it by dividing the hamming distance with the current KEYSIZE.
    Returns the KEYSIZE matching with the lowest normalized hamming distance.

    :param rawbyte: The byte to study (non-hexlified)
    :param mini: The lowest KEYSIZE to try
    :param maxi: The longest KEYSIZE to try
    :type rawbyte: byte
    :type mini: int
    :type maxi: int
    :return: The KEYSIZE matching with the lowest normalized hamming distance.
    :rtype: int
    """
    result = {'keysize': 0, 'hamming': 100}

    for KEYSIZE in range(mini, maxi):

        blocks = [rawbyte[KEYSIZE * i: KEYSIZE * (i+1)] for i in range(4)]

        haming = 0
        haming += hamming(blocks[0], blocks[1])
        haming += hamming(blocks[0], blocks[2])
        haming += hamming(blocks[0], blocks[3])
        haming += hamming(blocks[1], blocks[2])
        haming += hamming(blocks[1], blocks[3])
        haming += hamming(blocks[2], blocks[3])

        normalizedHamming = haming/KEYSIZE
        if normalizedHamming < result['hamming']:
            result['hamming'] = normalizedHamming
            result['keysize'] = KEYSIZE
    return(result['keysize'])


def divideBytesInBlocks(bytes_In, blocksSize):
    """
    Split 'bytes_In' into n blocks of 'blocksSize'.

    :param bytes_In: The byte to split in blocks (non-hexlified)
    :param blocksSize: The output blocks size.
    :type bytes_In: byte
    :type blocksSize: int
    :return: A list of blocks.
    :rtype: list of bytes
    """
    assert(isinstance(bytes_In, bytes))
    assert(isinstance(blocksSize, int))

    """
    On construit une liste de taille rangeSize qui va contenir des blocks de
    taille = blocksSize

    rangeSIze correspond à la longueur totale de bytes_In divisée par des
    blocks de taille blocksSize.

    Comme cette division peut donner un chiffre non entier, on l'arrondie
    et on y ajoute le reste de la division ainsi cela donnera la
    taille exacte qu'il nous faut
    """
    rangeSize = int(len(bytes_In) / blocksSize) + len(bytes_In) % blocksSize

    # construction des blocks
    blocks = [bytes_In[blocksSize * i: blocksSize * (i+1)] for i in range(rangeSize)]

    # On verifie qu'on a la même chose au debut et à la sortie
    test = b''
    for i in range(len(blocks)):
        test += blocks[i]
    assert(test == bytes_In)

    return(blocks)


def sizeBlocks2bytesBlocks(blocks):
    """
    Gather all the N' bytes of each blocks togethers in separated elements
    of a list.

    :param blocks: The list to compute
    :type blocks: list of bytes
    :return: A list of blocks.
    :rtype: list of bytes
    """
    assert(isinstance(blocks, list))
    blocksLen = len(blocks[0])
    nBlocks = len(blocks)

    # print("on a ", nBlocks, " blocks de taille", blocksLen)
    # On crée une liste contenant autant de champ que la la taille d'un block
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
                # Alors on verifie que l'on essaie pas de choper un octet qui
                # n'existe pas dans ce bloc
                if byte_i < len(blocks[block_n]):
                    outList[byte_i] += bytes([blocks[block_n][byte_i]])
    return(outList)


def aes_ecb(bData, bKey, action):
    """
    Decrypt or Encrypt bData with bKey in AES-128 ECB.

    :param bData: The data to encrypt (non-hexlified)
    :param bkey: The key used to encrypt bData (non-hexlified)
    :param action: Indicate if we want to encrypt of decrypt usign aes_ecb
    :type bData: byte
    :type bKey: byte
    :type action: 'encrypt' or 'decrypt'
    :return: The encrypted or decrypted result
    :rtype: byte
    """
    assert(isinstance(bData, bytes))
    assert(isinstance(bKey, bytes))
    assert(action == 'encrypt' or action == 'decrypt')

    # key long: 16 (AES-128), 24 (AES-192), or 32 (AES-256)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(bKey, AES.MODE_ECB, iv)

    if(action == 'decrypt'):
        return cipher.decrypt(bData)
    elif(action == 'encrypt'):
        return(cipher.encrypt(bData))


def aes_cbc(dataIn, key, iv, action):
    """
    Decrypt or Encrypt dataIn with key in AES-128 CBC using aes_ecb().

    :param dataIn: The data to encrypt (non-hexlified)
    :param key: The key used to encrypt bData (non-hexlified)
    :param action: Indicate if we want to encrypt of decrypt
    :type bData: byte
    :type bKey: byte
    :type action: 'encrypt' or 'decrypt'
    :return: The encrypted or decrypted result
    :rtype: byte
    """
    assert(isinstance(dataIn, bytes))
    assert(isinstance(key, bytes))
    assert(isinstance(iv, bytes))
    assert(action == 'encrypt' or action == 'decrypt')

    keysize = len(key)

    if(action == 'encrypt'):
        # ENCRYPT
        ciphertext = []
        plaintext = divideBytesInBlocks(dataIn, keysize)

        # On parcourt les blocs de notre plaintext
        for block in plaintext:
            # print(block)
            if block == plaintext[0]:
                xor_out = xor(iv, block)
            else:
                xor_out = xor(ciphertext[len(ciphertext)-1], block)
            aes = aes_ecb(xor_out, key, 'encrypt')
            ciphertext.append(aes)
        return(ciphertext)

    elif(action == 'decrypt'):
        plaintext = []
        ciphertext = divideBytesInBlocks(dataIn, keysize)
        # On parcourt les blocs de notre ciphertext
        for block in ciphertext:
            aes = aes_ecb(block, key, 'decrypt')
            if block == ciphertext[0]:
                xor_out = xor(iv, aes)
            else:
                xor_out = xor(lastblock, aes)
            lastblock = block
            plaintext.append(xor_out)

        return(plaintext)

def readFile(infile):
    """
    Open 'infile' and append each lines in a list.

    :param infile: The file to read.
    :type infile: string
    :return: The list of lines
    :rtype: list of bytes
    """
    f = open(infile, 'rb')
    data = []
    for line in f:
        data.append(line[:-1])

    return(data)


def PKCS7padder(plainTextBlock, paddingLenght):
    """Add bytes to get plainTextBlock as long as paddingLenght using PCKS#7.

    :param plainTextBlock: The plain text to padd (non-hexlified)
    :param paddingLenght: The block size
    :type plainTextBlock: bytes
    :type paddingLenght: int
    :return: The block with PCKS#7 applied
    :rtype: byte
    """
    assert(isinstance(plainTextBlock, bytes))
    assert(isinstance(paddingLenght, int))
    assert(len(plainTextBlock) <= paddingLenght)

    # We computer the size of our padding needs
    paddSize = paddingLenght - len(plainTextBlock)
    # We create our paddSize string
    padd = chr(paddSize).encode() * paddSize

    # And add it to our
    return plainTextBlock + padd
