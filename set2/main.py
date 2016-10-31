#!/usr/bin/env python3

import cryptopals


def chall9():
    string = b"YELLOW SUBMARINE"
    # print(PKCS7padder(string, 20))
    assert(cryptopals.PKCS7padder(string, 20) == b'YELLOW SUBMARINE\x04\x04\x04\x04')


def chall10():
    print()

if __name__ == '__main__':
    # chall9()
    chall10()
