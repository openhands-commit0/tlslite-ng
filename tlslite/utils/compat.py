"""Miscellaneous functions to mask Python version differences."""
import sys
import re
import os
import platform
import math
import binascii
import traceback
import time
import ecdsa
from binascii import a2b_hex, b2a_hex, a2b_base64, b2a_base64

def compat26Str(x):
    """Convert bytes or str to str"""
    if isinstance(x, str):
        return x
    elif isinstance(x, bytes):
        return x.decode('ascii')
    else:
        return str(x)

def compatLong(x):
    """Convert number to long"""
    if sys.version_info >= (3, 0):
        return int(x)
    else:
        return long(x)
if sys.version_info >= (3, 0):
    if sys.version_info < (3, 4):

        def compatHMAC(x):
            """Convert bytes-like input to format acceptable for HMAC."""
            if isinstance(x, str):
                return x.encode('ascii')
            return x
    else:

        def compatHMAC(x):
            """Convert bytes-like input to format acceptable for HMAC."""
            if isinstance(x, str):
                return x.encode('ascii')
            return x

    def compatAscii2Bytes(val):
        """Convert ASCII string to bytes."""
        if isinstance(val, str):
            return val.encode('ascii')
        return val

    def compat_b2a(val):
        """Convert an ASCII bytes string to string."""
        if isinstance(val, bytes):
            return val.decode('ascii')
        return val
    int_types = tuple([int])

    def formatExceptionTrace(e):
        """Return exception information formatted as string"""
        return str(traceback.format_exception(type(e), e, e.__traceback__))

    def time_stamp():
        """Returns system time as a float"""
        return time.time()

    def remove_whitespace(text):
        """Removes all whitespace from passed in string"""
        return re.sub(r'\s+', '', text)
    bytes_to_int = int.from_bytes

    def bit_length(val):
        """Return number of bits necessary to represent an integer."""
        return val.bit_length()

    def int_to_bytes(val, length=None, byteorder='big'):
        """Return number converted to bytes"""
        if length is None:
            length = byte_length(val)
        return val.to_bytes(length, byteorder=byteorder)
else:
    if sys.version_info < (2, 7) or sys.version_info < (2, 7, 4) or platform.system() == 'Java':

        def remove_whitespace(text):
            """Removes all whitespace from passed in string"""
            return re.sub(r'\s+', '', text)

        def bit_length(val):
            """Return number of bits necessary to represent an integer."""
            if val == 0:
                return 0
            return len(bin(val)[2:])
    else:

        def remove_whitespace(text):
            """Removes all whitespace from passed in string"""
            return re.sub(r'\s+', '', text)

        def bit_length(val):
            """Return number of bits necessary to represent an integer."""
            return val.bit_length()

    def compatAscii2Bytes(val):
        """Convert ASCII string to bytes."""
        if isinstance(val, str):
            return val.encode('ascii')
        return val

    def compat_b2a(val):
        """Convert an ASCII bytes string to string."""
        if isinstance(val, bytes):
            return val.decode('ascii')
        return val
    int_types = (int, long)

    def formatExceptionTrace(e):
        """Return exception information formatted as string"""
        return str(traceback.format_exc())

    def time_stamp():
        """Returns system time as a float"""
        return time.time()

    def bytes_to_int(val, byteorder):
        """Convert bytes to an int."""
        if byteorder == 'big':
            return int(b2a_hex(val), 16)
        else:
            return int(b2a_hex(val[::-1]), 16)

    def int_to_bytes(val, length=None, byteorder='big'):
        """Return number converted to bytes"""
        if length is None:
            length = byte_length(val)
        hex_str = '%x' % val
        if len(hex_str) % 2:
            hex_str = '0' + hex_str
        result = a2b_hex(hex_str)
        if len(result) < length:
            result = b'\x00' * (length - len(result)) + result
        if byteorder == 'little':
            result = result[::-1]
        return result

def byte_length(val):
    """Return number of bytes necessary to represent an integer."""
    length = val.bit_length()
    return (length + 7) // 8
try:
    getattr(ecdsa, 'NIST192p')
except AttributeError:
    ecdsaAllCurves = False
else:
    ecdsaAllCurves = True