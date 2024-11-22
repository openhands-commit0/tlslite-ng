from .compat import *
import binascii

def dePem(s, name):
    """Decode a PEM string into a bytearray of its payload.
    
    The input must contain an appropriate PEM prefix and postfix
    based on the input name string, e.g. for name="CERTIFICATE"::

      -----BEGIN CERTIFICATE-----
      MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
      ...
      KoZIhvcNAQEFBQADAwA5kw==
      -----END CERTIFICATE-----

    The first such PEM block in the input will be found, and its
    payload will be base64 decoded and returned.
    """
    start = "-----BEGIN " + name + "-----"
    end = "-----END " + name + "-----"
    s = str(s)

    # Find first PEM block
    start_index = s.find(start)
    if start_index == -1:
        raise SyntaxError("Missing PEM prefix")
    end_index = s.find(end, start_index + len(start))
    if end_index == -1:
        raise SyntaxError("Missing PEM postfix")

    # Get payload
    s = s[start_index + len(start):end_index]
    s = ''.join(s.splitlines())
    s = s.strip()
    return bytearray(binascii.a2b_base64(s))

def dePemList(s, name):
    """Decode a sequence of PEM blocks into a list of bytearrays.

    The input must contain any number of PEM blocks, each with the appropriate
    PEM prefix and postfix based on the input name string, e.g. for
    name="TACK BREAK SIG".  Arbitrary text can appear between and before and
    after the PEM blocks.  For example::

        Created by TACK.py 0.9.3 Created at 2012-02-01T00:30:10Z
        -----BEGIN TACK BREAK SIG-----
        ATKhrz5C6JHJW8BF5fLVrnQss6JnWVyEaC0p89LNhKPswvcC9/s6+vWLd9snYTUv
        YMEBdw69PUP8JB4AdqA3K6Ap0Fgd9SSTOECeAKOUAym8zcYaXUwpk0+WuPYa7Zmm
        SkbOlK4ywqt+amhWbg9txSGUwFO5tWUHT3QrnRlE/e3PeNFXLx5Bckg=
        -----END TACK BREAK SIG-----
        Created by TACK.py 0.9.3 Created at 2012-02-01T00:30:11Z
        -----BEGIN TACK BREAK SIG-----
        ATKhrz5C6JHJW8BF5fLVrnQss6JnWVyEaC0p89LNhKPswvcC9/s6+vWLd9snYTUv
        YMEBdw69PUP8JB4AdqA3K6BVCWfcjN36lx6JwxmZQncS6sww7DecFO/qjSePCxwM
        +kdDqX/9/183nmjx6bf0ewhPXkA0nVXsDYZaydN8rJU1GaMlnjcIYxY=
        -----END TACK BREAK SIG-----
    
    All such PEM blocks will be found, decoded, and return in an ordered list
    of bytearrays, which may have zero elements if not PEM blocks are found.
    """
    bList = []
    start = "-----BEGIN " + name + "-----"
    end = "-----END " + name + "-----"
    s = str(s)
    while True:
        start_index = s.find(start)
        if start_index == -1:
            break
        end_index = s.find(end, start_index + len(start))
        if end_index == -1:
            break
        # Get the payload
        payload = s[start_index + len(start):end_index]
        payload = ''.join(payload.splitlines())
        payload = payload.strip()
        bList.append(bytearray(binascii.a2b_base64(payload)))
        s = s[end_index + len(end):]
    return bList

def pem(b, name):
    """Encode a payload bytearray into a PEM string.
    
    The input will be base64 encoded, then wrapped in a PEM prefix/postfix
    based on the name string, e.g. for name="CERTIFICATE"::
    
        -----BEGIN CERTIFICATE-----
        MIIBXDCCAUSgAwIBAgIBADANBgkqhkiG9w0BAQUFADAPMQ0wCwYDVQQDEwRUQUNL
        ...
        KoZIhvcNAQEFBQADAwA5kw==
        -----END CERTIFICATE-----
    """
    s = binascii.b2a_base64(b).decode()
    s = s.rstrip()  # remove newline from b2a_base64
    s = "-----BEGIN " + name + "-----\n" + \
        s + "\n" + \
        "-----END " + name + "-----\n"
    return s

def pemSniff(s, name):
    """Check if string appears to be a PEM-encoded payload with the specified name.

    :type s: str
    :param s: The string to check.

    :type name: str
    :param name: The expected name of the PEM payload.

    :rtype: bool
    :returns: True if the string appears to be a PEM-encoded payload with the
        specified name, False otherwise.
    """
    start = "-----BEGIN " + name + "-----"
    end = "-----END " + name + "-----"
    s = str(s)
    start_index = s.find(start)
    if start_index == -1:
        return False
    end_index = s.find(end, start_index + len(start))
    if end_index == -1:
        return False
    return True