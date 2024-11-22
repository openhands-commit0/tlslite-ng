"""AESCCM with CTR and CBC from m2crypto"""
from tlslite.utils.cryptomath import m2cryptoLoaded
from tlslite.utils.aesccm import AESCCM
from tlslite.utils import openssl_aes
if m2cryptoLoaded:
    class OPENSSL_AESCCM(AESCCM):

        def __init__(self, key, implementation, rawAesEncrypt, tagLength):
            super(OPENSSL_AESCCM, self).__init__(key, implementation, rawAesEncrypt, tagLength)
            self._ctr = openssl_aes.new(key, 6, bytearray(b'\x00' * 16))
            self._cbc = openssl_aes.new(key, 2, bytearray(b'\x00' * 16))