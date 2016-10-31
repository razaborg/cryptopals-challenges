#!/usr/bin/env python3

from cryptopals import *


def chall9():
    string = b"YELLOW SUBMARINE"
    # print(PKCS7padder(string, 20))
    assert(PKCS7padder(string, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04')


if __name__ == '__main__':
    chall9()
