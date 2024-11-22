"""cryptomath module

This module has basic math/crypto code."""
from __future__ import print_function
import os
import math
import base64
import binascii
from .compat import compat26Str, compatHMAC, compatLong, bytes_to_int, int_to_bytes, bit_length, byte_length
from .codec import Writer
from . import tlshashlib as hashlib
from . import tlshmac as hmac
try:
    from M2Crypto import m2
    m2cryptoLoaded = True
    M2CRYPTO_AES_CTR = False
    if hasattr(m2, 'aes_192_ctr'):
        M2CRYPTO_AES_CTR = True
    try:
        with open('/proc/sys/crypto/fips_enabled', 'r') as fipsFile:
            if '1' in fipsFile.read():
                m2cryptoLoaded = False
    except (IOError, OSError):
        m2cryptoLoaded = True
    if not hasattr(m2, 'aes_192_cbc'):
        m2cryptoLoaded = False
except ImportError:
    m2cryptoLoaded = False
try:
    import gmpy
    gmpy.mpz
    gmpyLoaded = True
except ImportError:
    gmpyLoaded = False
try:
    from gmpy2 import powmod
    GMPY2_LOADED = True
except ImportError:
    GMPY2_LOADED = False
if GMPY2_LOADED:
    from gmpy2 import mpz
elif gmpyLoaded:
    from gmpy import mpz
try:
    import Crypto.Cipher.AES
    try:
        Crypto.Cipher.AES.AESCipher(b'2' * (128 // 8))
        pycryptoLoaded = True
    except AttributeError:
        pycryptoLoaded = False
except ImportError:
    pycryptoLoaded = False
import zlib
assert len(zlib.compress(os.urandom(1000))) > 900
prngName = 'os.urandom'

def MD5(b):
    """Return a MD5 digest of data"""
    return hashlib.md5(compat26Str(b)).digest()

def SHA1(b):
    """Return a SHA1 digest of data"""
    return hashlib.sha1(compat26Str(b)).digest()

def HMAC_MD5(k, b):
    """Return HMAC using MD5"""
    return secureHMAC(k, b, "md5")

def HMAC_SHA1(k, b):
    """Return HMAC using SHA1"""
    return secureHMAC(k, b, "sha1")

def HMAC_SHA256(k, b):
    """Return HMAC using SHA256"""
    return secureHMAC(k, b, "sha256")

def HMAC_SHA384(k, b):
    """Return HMAC using SHA384"""
    return secureHMAC(k, b, "sha384")

def secureHash(data, algorithm):
    """Return a digest of `data` using `algorithm`"""
    hashInstance = hashlib.new(algorithm)
    hashInstance.update(compat26Str(data))
    return hashInstance.digest()

def secureHMAC(k, b, algorithm):
    """Return a HMAC using `b` and `k` using `algorithm`"""
    k = compatHMAC(k)
    b = compatHMAC(b)
    return hmac.new(k, b, getattr(hashlib, algorithm)).digest()

def getRandomBytes(howMany):
    """Return a specified number of random bytes."""
    return os.urandom(howMany)

def getRandomNumber(low, high):
    """Return a random number in the range [low, high]."""
    if low >= high:
        raise ValueError("Low must be lower than high")
    howManyBits = len(bin(high - low)[2:])
    howManyBytes = (howManyBits + 7) // 8
    while True:
        bytes = getRandomBytes(howManyBytes)
        n = bytesToNumber(bytes)
        if n >= low and n <= high:
            return n

def HKDF_expand_label(secret, label, hashValue, length, algorithm):
    """
    TLS1.3 key derivation function (HKDF-Expand-Label).

    :param bytearray secret: the key from which to derive the keying material
    :param bytearray label: label used to differentiate the keying materials
    :param bytearray hashValue: bytes used to "salt" the produced keying
        material
    :param int length: number of bytes to produce
    :param str algorithm: name of the secure hash algorithm used as the
        basis of the HKDF
    :rtype: bytearray
    """
    hkdf_label = Writer()
    hkdf_label.add(length, 2)
    hkdf_label.addVarSeq(b"tls13 " + label, 1, 1)
    hkdf_label.addVarSeq(hashValue, 1, 1)
    return HKDF_expand(secret, hkdf_label.bytes(), length, algorithm)

def derive_secret(secret, label, handshake_hashes, algorithm):
    """
    TLS1.3 key derivation function (Derive-Secret).

    :param bytearray secret: secret key used to derive the keying material
    :param bytearray label: label used to differentiate they keying materials
    :param HandshakeHashes handshake_hashes: hashes of the handshake messages
        or `None` if no handshake transcript is to be used for derivation of
        keying material
    :param str algorithm: name of the secure hash algorithm used as the
        basis of the HKDF algorithm - governs how much keying material will
        be generated
    :rtype: bytearray
    """
    if handshake_hashes is None:
        hash_value = secureHash(b"", algorithm)
    else:
        hash_value = handshake_hashes.digest(algorithm)
    return HKDF_expand_label(secret, label, hash_value,
                           getattr(hashlib, algorithm).digest_size,
                           algorithm)

def bytesToNumber(b, endian='big'):
    """
    Convert a number stored in bytearray to an integer.

    By default assumes big-endian encoding of the number.
    """
    return bytes_to_int(b, endian)

def numberToByteArray(n, howManyBytes=None, endian='big'):
    """
    Convert an integer into a bytearray, zero-pad to howManyBytes.

    The returned bytearray may be smaller than howManyBytes, but will
    not be larger.  The returned bytearray will contain a big- or little-endian
    encoding of the input integer (n). Big endian encoding is used by default.
    """
    return bytearray(int_to_bytes(n, howManyBytes, endian))

def mpiToNumber(mpi):
    """Convert a MPI (OpenSSL bignum string) to an integer."""
    byte_array = bytearray(mpi)
    byte_len = (byte_array[0] * 256 + byte_array[1] + 7) // 8
    return bytesToNumber(byte_array[2:2 + byte_len])
numBits = bit_length
numBytes = byte_length
if GMPY2_LOADED:

    def invMod(a, b):
        """Return inverse of a mod b, zero if none."""
        try:
            return int(powmod(mpz(a), -1, mpz(b)))
        except (ValueError, ZeroDivisionError):
            return 0
else:

    def invMod(a, b):
        """Return inverse of a mod b, zero if none."""
        s = 0
        t = 1
        r = b
        old_s = 1
        old_t = 0
        old_r = a
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t
        if old_r != 1:
            return 0
        while old_s < 0:
            old_s += b
        return old_s
if gmpyLoaded or GMPY2_LOADED:
    powMod = powmod
else:
    powMod = pow

def divceil(divident, divisor):
    """Integer division with rounding up"""
    return (divident + divisor - 1) // divisor

def isPrime(n, iterations=8):
    """Returns True if n is prime with high probability"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n & 1 == 0:
        return False

    # Write n-1 as d * 2^s by factoring powers of 2 from n-1
    s = 0
    d = n - 1
    while d & 1 == 0:
        s += 1
        d >>= 1

    # Try to divide n by a few small primes
    for i in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]:
        if n % i == 0:
            return n == i

    # Do iterations of Miller-Rabin testing
    for i in range(iterations):
        a = bytes_to_int(os.urandom(numBytes(n)))
        if a == 0 or a >= n:
            a = 1
        a = powMod(a, d, n)
        if a == 1:
            continue
        for r in range(s):
            if a == n - 1:
                break
            a = powMod(a, 2, n)
            if a == 1:
                return False
        else:
            return False
    return True

def getRandomPrime(bits, display=False):
    """
    Generate a random prime number of a given size.

    the number will be 'bits' bits long (i.e. generated number will be
    larger than `(2^(bits-1) * 3 ) / 2` but smaller than 2^bits.
    """
    while True:
        n = bytes_to_int(os.urandom(bits // 8 + 1))
        n |= 2 ** (bits - 1)  # Set high bit
        n &= ~(1 << (bits - 1)) - 1  # Clear low bits
        if display:
            print(".", end=' ')
        if isPrime(n, iterations=30):
            return n

def getRandomSafePrime(bits, display=False):
    """Generate a random safe prime.

    Will generate a prime `bits` bits long (see getRandomPrime) such that
    the (p-1)/2 will also be prime.
    """
    while True:
        q = getRandomPrime(bits - 1, display)
        p = 2 * q + 1
        if isPrime(p, iterations=30):
            return p