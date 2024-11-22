"""AESGCM with CTR from m2crypto"""
from tlslite.utils.cryptomath import m2cryptoLoaded
from tlslite.utils.aesgcm import AESGCM
from tlslite.utils import openssl_aes
from tlslite.utils.rijndael import Rijndael
if m2cryptoLoaded:
    class OPENSSL_AESGCM(AESGCM):

        def __init__(self, key, implementation, rawAesEncrypt):
            super(OPENSSL_AESGCM, self).__init__(key, implementation, rawAesEncrypt)
            self._ctr = openssl_aes.new(key, 6, bytearray(b'\x00' * 16))