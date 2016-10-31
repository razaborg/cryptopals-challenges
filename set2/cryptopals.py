#!/usr/bin/env python3
from binascii import hexlify, unhexlify

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
