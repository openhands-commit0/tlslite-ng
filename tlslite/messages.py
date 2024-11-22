"""Classes representing TLS messages."""
from .utils.compat import *
from .utils.cryptomath import *
from .errors import *
from .utils.codec import *
from .constants import *
from .x509 import X509
from .x509certchain import X509CertChain
from .utils.tackwrapper import *
from .utils.deprecations import deprecated_attrs, deprecated_params
from .extensions import *
from .utils.format_output import none_as_unknown

class RecordHeader(object):
    """Generic interface to SSLv2 and SSLv3 (and later) record headers."""

    def __init__(self, ssl2):
        """Define instance variables."""
        self.type = 0
        self.version = (0, 0)
        self.length = 0
        self.ssl2 = ssl2

class RecordHeader3(RecordHeader):
    """SSLv3 (and later) TLS record header."""

    def __init__(self):
        """Define a SSLv3 style class."""
        super(RecordHeader3, self).__init__(ssl2=False)

    def create(self, version, type, length):
        """Set object values for writing (serialisation)."""
        pass

    def write(self):
        """Serialise object to bytearray."""
        pass

    def parse(self, parser):
        """Deserialise object from Parser."""
        pass

    def __str__(self):
        return 'SSLv3 record,version({0[0]}.{0[1]}),content type({1}),length({2})'.format(self.version, self.typeName, self.length)

    def __repr__(self):
        return 'RecordHeader3(type={0}, version=({1[0]}.{1[1]}), length={2})'.format(self.type, self.version, self.length)

class RecordHeader2(RecordHeader):
    """
    SSLv2 record header.

    :vartype padding: int
    :ivar padding: number of bytes added at end of message to make it multiple
        of block cipher size
    :vartype securityEscape: boolean
    :ivar securityEscape: whether the record contains a security escape message
    """

    def __init__(self):
        """Define a SSLv2 style class."""
        super(RecordHeader2, self).__init__(ssl2=True)
        self.padding = 0
        self.securityEscape = False

    def parse(self, parser):
        """Deserialise object from Parser."""
        pass

    def create(self, length, padding=0, securityEscape=False):
        """Set object's values."""
        pass

    def write(self):
        """Serialise object to bytearray."""
        pass

class Message(object):
    """Generic TLS message."""

    def __init__(self, contentType, data):
        """
        Initialize object with specified contentType and data.

        :type contentType: int
        :param contentType: TLS record layer content type of associated data
        :type data: bytearray
        :param data: data
        """
        self.contentType = contentType
        self.data = data

    def write(self):
        """Return serialised object data."""
        pass

class Alert(object):

    def __init__(self):
        self.contentType = ContentType.alert
        self.level = 0
        self.description = 0

    def __str__(self):
        return 'Alert, level:{0}, description:{1}'.format(self.levelName, self.descriptionName)

    def __repr__(self):
        return 'Alert(level={0}, description={1})'.format(self.level, self.description)

class HandshakeMsg(object):

    def __init__(self, handshakeType):
        self.contentType = ContentType.handshake
        self.handshakeType = handshakeType

    def __eq__(self, other):
        """Check if other object represents the same data as this object."""
        if hasattr(self, 'write') and hasattr(other, 'write'):
            return self.write() == other.write()
        else:
            return False

    def __ne__(self, other):
        """Check if other object represents different data as this object."""
        return not self.__eq__(other)

class HelloMessage(HandshakeMsg):
    """
    Class for sharing code between :py:class:`ClientHello` and
    :py:class:`ServerHello`.
    """

    def __init__(self, *args, **kwargs):
        """Initialize object."""
        super(HelloMessage, self).__init__(*args, **kwargs)
        self.extensions = None

    def getExtension(self, extType):
        """
        Return extension of given type if present, None otherwise.

        :rtype: ~tlslite.extensions.TLSExtension
        :raises TLSInternalError: when there are multiple extensions of the
            same type
        """
        pass

    def addExtension(self, ext):
        """
        Add extension to internal list of extensions.

        :type ext: TLSExtension
        :param ext: extension object to add to list
        """
        pass

    def _addExt(self, extType):
        """Add en empty extension of given type, if not already present"""
        pass

    def _removeExt(self, extType):
        """Remove extension of given type"""
        pass

    def _addOrRemoveExt(self, extType, add):
        """
        Remove or add an empty extension of given type.

        :type extType: int
        :param extType: numeric id of extension to add or remove
        :type add: boolean
        :param add: whether to add (True) or remove (False) the extension
        """
        pass

class ClientHello(HelloMessage):
    """
    Class for handling the ClientHello SSLv2/SSLv3/TLS message.

    :vartype certificate_types: list
    :ivar certificate_types: list of supported certificate types
        (deprecated)
    :vartype srp_username: bytearray
    :ivar srp_username: name of the user in SRP extension (deprecated)

    :vartype ~.supports_npn: boolean
    :ivar ~.supports_npn: NPN extension presence (deprecated)

    :vartype ~.tack: boolean
    :ivar ~.tack: TACK extension presence (deprecated)

    :vartype ~.server_name: bytearray
    :ivar ~.server_name: first host_name (type 0) present in SNI extension
        (deprecated)

    :vartype extensions: list of :py:class:`TLSExtension`
    :ivar extensions: list of TLS extensions parsed from wire or to send, see
        :py:class:`TLSExtension` and child classes for exact examples
    """

    def __init__(self, ssl2=False):
        super(ClientHello, self).__init__(HandshakeType.client_hello)
        self.ssl2 = ssl2
        self.client_version = (0, 0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suites = []
        self.compression_methods = []

    def __str__(self):
        """
        Return human readable representation of Client Hello.

        :rtype: str
        """
        if self.session_id.count(bytearray(b'\x00')) == len(self.session_id) and len(self.session_id) != 0:
            session = "bytearray(b'\\x00'*{0})".format(len(self.session_id))
        else:
            session = repr(self.session_id)
        ret = 'client_hello,version({0[0]}.{0[1]}),random(...),session ID({1!s}),cipher suites({2}),compression methods({3!r})'.format(self.client_version, session, self._ciphers_to_str(), self.compression_methods)
        if self.extensions is not None:
            ret += ',extensions({0!r})'.format(self.extensions)
        return ret

    def __repr__(self):
        """
        Return machine readable representation of Client Hello.

        :rtype: str
        """
        return 'ClientHello(ssl2={0}, client_version=({1[0]}.{1[1]}), random={2!r}, session_id={3!r}, cipher_suites={4}, compression_methods={5}, extensions={6})'.format(self.ssl2, self.client_version, self.random, self.session_id, self._ciphers_to_str(), self.compression_methods, self.extensions)

    @property
    def certificate_types(self):
        """
        Return the list of certificate types supported.

        .. deprecated:: 0.5
            use extensions field to get the extension for inspection
        """
        if self.extensions is None:
            return None
        for ext in self.extensions:
            if isinstance(ext, ClientCertTypeExtension):
                return ext.cert_types
        return None

    @certificate_types.setter
    def certificate_types(self, val):
        """
        Set list of supported certificate types.

        Sets the list of supported types to list given in :py:obj:`val` if the
        cert_type extension is present. Creates the extension and places it
        last in the list otherwise.

        :type val: list
        :param val: list of supported certificate types by client encoded as
            single byte integers
        """
        if self.extensions is None:
            self.extensions = []

        for ext in self.extensions:
            if isinstance(ext, ClientCertTypeExtension):
                ext.cert_types = val
                return

        ext = ClientCertTypeExtension().create(val)
        self.extensions.append(ext)

    @property
    def srp_username(self):
        """
        Return username for the SRP.

        .. deprecated:: 0.5
            use extensions field to get the extension for inspection
        """
        if self.extensions is None:
            return None
        for ext in self.extensions:
            if isinstance(ext, SRPExtension):
                return ext.srp_username
        return None

    @srp_username.setter
    def srp_username(self, name):
        """
        Set the username for SRP.

        :type name: bytearray
        :param name: UTF-8 encoded username
        """
        if self.extensions is None:
            self.extensions = []

        for ext in self.extensions:
            if isinstance(ext, SRPExtension):
                ext.srp_username = name
                return

        ext = SRPExtension().create(name)
        self.extensions.append(ext)

    @property
    def tack(self):
        """
        Return whether the client supports TACK.

        .. deprecated:: 0.5
            use extensions field to get the extension for inspection

        :rtype: boolean
        """
        if self.extensions is None:
            return False
        for ext in self.extensions:
            if isinstance(ext, TACKExtension):
                return True
        return False

    @tack.setter
    def tack(self, present):
        """
        Create or delete the TACK extension.

        :type present: boolean
        :param present: True will create extension while False will remove
            extension from client hello
        """
        if self.extensions is None:
            self.extensions = []

        for ext in self.extensions:
            if isinstance(ext, TACKExtension):
                if not present:
                    self.extensions.remove(ext)
                return

        if present:
            ext = TACKExtension().create()
            self.extensions.append(ext)

    @property
    def supports_npn(self):
        """
        Return whether client supports NPN extension.

        .. deprecated:: 0.5
            use extensions field to get the extension for inspection

        :rtype: boolean
        """
        if self.extensions is None:
            return False
        for ext in self.extensions:
            if isinstance(ext, NPNExtension):
                return True
        return False

    @supports_npn.setter
    def supports_npn(self, present):
        """
        Create or delete the NPN extension.

        :type present: boolean
        :param present: selects whatever to create or remove the extension
            from list of supported ones
        """
        if self.extensions is None:
            self.extensions = []

        for ext in self.extensions:
            if isinstance(ext, NPNExtension):
                if not present:
                    self.extensions.remove(ext)
                return

        if present:
            ext = NPNExtension().create([])
            self.extensions.append(ext)

    @property
    def server_name(self):
        """
        Return first host_name present in SNI extension.

        .. deprecated:: 0.5
            use extensions field to get the extension for inspection

        :rtype: bytearray
        """
        if self.extensions is None:
            return None
        for ext in self.extensions:
            if isinstance(ext, SNIExtension):
                if ext.host_names:
                    return ext.host_names[0]
        return None

    @server_name.setter
    def server_name(self, hostname):
        """
        Set the first host_name present in SNI extension.

        :type hostname: bytearray
        :param hostname: name of the host_name to set
        """
        if self.extensions is None:
            self.extensions = []

        for ext in self.extensions:
            if isinstance(ext, SNIExtension):
                ext.host_names = [hostname]
                return

        ext = SNIExtension().create([hostname])
        self.extensions.append(ext)

    def create(self, version, random, session_id, cipher_suites, certificate_types=None, srpUsername=None, tack=False, supports_npn=None, serverName=None, extensions=None):
        """
        Create a ClientHello message for sending.

        :type version: tuple
        :param version: the highest supported TLS version encoded as two int
            tuple

        :type random: bytearray
        :param random: client provided random value, in old versions of TLS
            (before 1.2) the first 32 bits should include system time, also
            used as the "challenge" field in SSLv2

        :type session_id: bytearray
        :param session_id: ID of session, set when doing session resumption

        :type cipher_suites: list
        :param cipher_suites: list of ciphersuites advertised as supported

        :type certificate_types: list
        :param certificate_types: list of supported certificate types, uses
            TLS extension for signalling, as such requires TLS1.0 to work

        :type srpUsername: bytearray
        :param srpUsername: utf-8 encoded username for SRP, TLS extension

        :type tack: boolean
        :param tack: whatever to advertise support for TACK, TLS extension

        :type supports_npn: boolean
        :param supports_npn: whatever to advertise support for NPN, TLS
            extension

        :type serverName: bytearray
        :param serverName: the hostname to request in server name indication
            extension, TLS extension. Note that SNI allows to set multiple
            hostnames and values that are not hostnames, use
            :py:class:`~.extensions.SNIExtension`
            together with :py:obj:`extensions` to use it.

        :type extensions: list of :py:class:`~.extensions.TLSExtension`
        :param extensions: list of extensions to advertise
        """
        self.client_version = version
        self.random = random
        self.session_id = session_id
        self.cipher_suites = cipher_suites
        self.compression_methods = [0]  # only null compression
        self.extensions = extensions

        if certificate_types is not None:
            self.certificate_types = certificate_types
        if srpUsername is not None:
            self.srp_username = srpUsername
        if tack:
            self.tack = tack
        if supports_npn is not None:
            self.supports_npn = supports_npn
        if serverName is not None:
            self.server_name = serverName

    def parse(self, p):
        """Deserialise object from on the wire data."""
        if self.ssl2:
            self.client_version = (p.get(1), p.get(1))
            cipher_suites_length = p.get(2)
            session_id_length = p.get(2)
            challenge_length = p.get(2)
            self.cipher_suites = []
            for i in range(cipher_suites_length // 3):
                self.cipher_suites.append(p.get(3))
            self.session_id = p.getFixBytes(session_id_length)
            self.random = p.getFixBytes(challenge_length)
            self.compression_methods = [0]  # SSL2 has no compression
            return None

        self.client_version = (p.get(1), p.get(1))
        self.random = p.getFixBytes(32)
        session_id_length = p.get(1)
        self.session_id = p.getFixBytes(session_id_length)
        cipher_suites_length = p.get(2)
        self.cipher_suites = []
        for i in range(cipher_suites_length // 2):
            self.cipher_suites.append(p.get(2))
        compression_methods_length = p.get(1)
        self.compression_methods = []
        for i in range(compression_methods_length):
            self.compression_methods.append(p.get(1))

        if p.getRemainingLength() > 0:
            self.extensions = []
            extensions_length = p.get(2)
            while p.getRemainingLength() > 0:
                ext = TLSExtension().parse(p)
                self.extensions.append(ext)

    def _writeSSL2(self):
        """Serialise SSLv2 object to on the wire data."""
        w = Writer()
        w.add(self.client_version[0], 1)
        w.add(self.client_version[1], 1)
        w.add(len(self.cipher_suites) * 3, 2)
        w.add(len(self.session_id), 2)
        w.add(len(self.random), 2)
        for cipher_suite in self.cipher_suites:
            w.addFixSeq(bytearray([0x00, cipher_suite >> 8, cipher_suite & 0xFF]), 3)
        w.addFixSeq(self.session_id, len(self.session_id))
        w.addFixSeq(self.random, len(self.random))
        return w.bytes

    def _write(self):
        """Serialise SSLv3 or TLS object to on the wire data."""
        w = Writer()
        w.add(self.client_version[0], 1)
        w.add(self.client_version[1], 1)
        w.addFixSeq(self.random, 32)
        w.addVarSeq(self.session_id, 1, 1)
        w.addVarSeq(Writer.array_to_bytes(self.cipher_suites, 2), 2, 2)
        w.addVarSeq(Writer.array_to_bytes(self.compression_methods, 1), 1, 1)

        if self.extensions is not None:
            w2 = Writer()
            for ext in self.extensions:
                w2.bytes += ext.write()
            w.add(len(w2.bytes), 2)
            w.bytes += w2.bytes
        return w.bytes

    def psk_truncate(self):
        """Return a truncated encoding of message without binders.

        In TLS 1.3, with PSK exchange, the ClientHello message is signed
        by the binders in it. Return the part that is symmetrically signed
        by those binders.

        See "PSK Binder" in draft-ietf-tls-tls13-23.

        :rtype: bytearray
        """
        if not self.extensions:
            return self.write()

        psk_ext = None
        for ext in self.extensions:
            if isinstance(ext, PreSharedKeyExtension):
                psk_ext = ext
                break

        if not psk_ext:
            return self.write()

        # remove the binders from the extension
        old_binders = psk_ext.binders
        psk_ext.binders = None
        ret = self.write()
        psk_ext.binders = old_binders
        return ret

    def write(self):
        """Serialise object to on the wire data."""
        if self.ssl2:
            return self._writeSSL2()
        return self._write()

class HelloRequest(HandshakeMsg):
    """
    Handling of Hello Request messages.
    """

    def __init__(self):
        super(HelloRequest, self).__init__(HandshakeType.hello_request)

class ServerHello(HelloMessage):
    """
    Handling of Server Hello messages.

    :vartype server_version: tuple
    :ivar server_version: protocol version encoded as two int tuple

    :vartype random: bytearray
    :ivar random: server random value

    :vartype session_id: bytearray
    :ivar session_id: session identifier for resumption

    :vartype cipher_suite: int
    :ivar cipher_suite: server selected cipher_suite

    :vartype compression_method: int
    :ivar compression_method: server selected compression method

    :vartype next_protos: list of bytearray
    :ivar next_protos: list of advertised protocols in NPN extension

    :vartype next_protos_advertised: list of bytearray
    :ivar next_protos_advertised: list of protocols advertised in NPN extension

    :vartype certificate_type: int
    :ivar certificate_type: certificate type selected by server

    :vartype extensions: list
    :ivar extensions: list of TLS extensions present in server_hello message,
        see :py:class:`~.extensions.TLSExtension` and child classes for exact
        examples
    """

    def __init__(self):
        """Initialise ServerHello object."""
        super(ServerHello, self).__init__(HandshakeType.server_hello)
        self.server_version = (0, 0)
        self.random = bytearray(32)
        self.session_id = bytearray(0)
        self.cipher_suite = 0
        self.compression_method = 0
        self._tack_ext = None

    def __str__(self):
        base = 'server_hello,length({0}),version({1[0]}.{1[1]}),random(...),session ID({2!r}),cipher({3:#x}),compression method({4})'.format(len(self.write()) - 4, self.server_version, self.session_id, self.cipher_suite, self.compression_method)
        if self.extensions is None:
            return base
        ret = ',extensions['
        ret += ','.join((repr(x) for x in self.extensions))
        ret += ']'
        return base + ret

    def __repr__(self):
        return 'ServerHello(server_version=({0[0]}, {0[1]}), random={1!r}, session_id={2!r}, cipher_suite={3}, compression_method={4}, _tack_ext={5}, extensions={6!r})'.format(self.server_version, self.random, self.session_id, self.cipher_suite, self.compression_method, self._tack_ext, self.extensions)

    @property
    def tackExt(self):
        """Return the TACK extension."""
        pass

    @tackExt.setter
    def tackExt(self, val):
        """Set the TACK extension."""
        pass

    @property
    def certificate_type(self):
        """
        Return the certificate type selected by server.

        :rtype: int
        """
        pass

    @certificate_type.setter
    def certificate_type(self, val):
        """
        Set the certificate type supported.

        :type val: int
        :param val: type of certificate
        """
        pass

    @property
    def next_protos(self):
        """
        Return the advertised protocols in NPN extension.

        :rtype: list of bytearrays
        """
        pass

    @next_protos.setter
    def next_protos(self, val):
        """
        Set the advertised protocols in NPN extension.

        :type val: list
        :param val: list of protocols to advertise as UTF-8 encoded names
        """
        pass

    @property
    def next_protos_advertised(self):
        """
        Return the advertised protocols in NPN extension.

        :rtype: list of bytearrays
        """
        pass

    @next_protos_advertised.setter
    def next_protos_advertised(self, val):
        """
        Set the advertised protocols in NPN extension.

        :type val: list
        :param val: list of protocols to advertise as UTF-8 encoded names
        """
        pass

    def create(self, version, random, session_id, cipher_suite, certificate_type=None, tackExt=None, next_protos_advertised=None, extensions=None):
        """Initialize the object for deserialisation."""
        pass

class ServerHello2(HandshakeMsg):
    """
    SERVER-HELLO message from SSLv2.

    :vartype session_id_hit: int
    :ivar session_id_hit: non zero if the client provided session ID was
        matched in server's session cache

    :vartype certificate_type: int
    :ivar certificate_type: type of certificate sent

    :vartype server_version: tuple of ints
    :ivar server_version: protocol version selected by server

    :vartype certificate: bytearray
    :ivar certificate: certificate sent by server

    :vartype ciphers: array of int
    :ivar ciphers: list of ciphers supported by server

    :vartype session_id: bytearray
    :ivar session_id: idendifier of negotiated session
    """

    def __init__(self):
        super(ServerHello2, self).__init__(SSL2HandshakeType.server_hello)
        self.session_id_hit = 0
        self.certificate_type = 0
        self.server_version = (0, 0)
        self.certificate = bytearray(0)
        self.ciphers = []
        self.session_id = bytearray(0)

    def create(self, session_id_hit, certificate_type, server_version, certificate, ciphers, session_id):
        """Initialize fields of the SERVER-HELLO message."""
        pass

    def write(self):
        """Serialise object to on the wire data."""
        pass

    def parse(self, parser):
        """Deserialise object from on the wire data."""
        pass

class CertificateEntry(object):
    """
    Object storing a single certificate from TLS 1.3.

    Stores a certificate (or possibly a raw public key) together with
    associated extensions
    """

    def __init__(self, certificateType):
        """Initialise the object for given certificate type."""
        self.certificateType = certificateType
        self.certificate = None
        self.extensions = None

    def create(self, certificate, extensions):
        """Set all values of the certificate entry."""
        pass

    def write(self):
        """Serialise the object."""
        pass

    def parse(self, parser):
        """Deserialise the object from on the wire data."""
        pass

    def __repr__(self):
        return 'CertificateEntry(certificate={0!r}, extensions={1!r})'.format(self.certificate, self.extensions)

@deprecated_attrs({'cert_chain': 'certChain'})
class Certificate(HandshakeMsg):

    def __init__(self, certificateType, version=(3, 2)):
        HandshakeMsg.__init__(self, HandshakeType.certificate)
        self.certificateType = certificateType
        self._cert_chain = None
        self.version = version
        self.certificate_list = []
        self.certificate_request_context = None

    @property
    def cert_chain(self):
        """Getter for the cert_chain property."""
        pass

    @cert_chain.setter
    def cert_chain(self, cert_chain):
        """Setter for the cert_chain property."""
        pass

    @deprecated_params({'cert_chain': 'certChain'})
    def create(self, cert_chain, context=b''):
        """Initialise fields of the class."""
        pass

    def __repr__(self):
        if self.version <= (3, 3):
            return 'Certificate(cert_chain={0!r})'.format(self.cert_chain.x509List)
        return 'Certificate(request_context={0!r}, certificate_list={1!r})'.format(self.certificate_request_context, self.certificate_list)

class CertificateRequest(HelloMessage):

    def __init__(self, version):
        super(CertificateRequest, self).__init__(HandshakeType.certificate_request)
        self.certificate_types = []
        self.certificate_authorities = []
        self.version = version
        self.certificate_request_context = b''
        self.extensions = None

    @property
    def supported_signature_algs(self):
        """
        Returns the list of supported algorithms.

        We store the list in an extension even for TLS < 1.3
        Extensions are used/valid only for TLS 1.3 but they are a good
        unified storage mechanism for all versions.
        """
        pass

    def create(self, certificate_types=None, certificate_authorities=None, sig_algs=None, context=b'', extensions=None):
        """
            Creates a Certificate Request message.
            For TLS 1.3 only the context and extensions parameters should be
            provided, the others are ignored.
            For TLS versions below 1.3 instead only the first three parameters
            are considered.
        """
        pass

class ServerKeyExchange(HandshakeMsg):
    """
    Handling TLS Handshake protocol Server Key Exchange messages.

    :vartype cipherSuite: int
    :cvar cipherSuite: id of ciphersuite selected in Server Hello message
    :vartype srp_N: int
    :cvar srp_N: SRP protocol prime
    :vartype srp_N_len: int
    :cvar srp_N_len: length of srp_N in bytes
    :vartype srp_g: int
    :cvar srp_g: SRP protocol generator
    :vartype srp_g_len: int
    :cvar srp_g_len: length of srp_g in bytes
    :vartype srp_s: bytearray
    :cvar srp_s: SRP protocol salt value
    :vartype srp_B: int
    :cvar srp_B: SRP protocol server public value
    :vartype srp_B_len: int
    :cvar srp_B_len: length of srp_B in bytes
    :vartype dh_p: int
    :cvar dh_p: FFDHE protocol prime
    :vartype dh_p_len: int
    :cvar dh_p_len: length of dh_p in bytes
    :vartype dh_g: int
    :cvar dh_g: FFDHE protocol generator
    :vartype dh_g_len: int
    :cvar dh_g_len: length of dh_g in bytes
    :vartype dh_Ys: int
    :cvar dh_Ys: FFDH protocol server key share
    :vartype dh_Ys_len: int
    :cvar dh_Ys_len: length of dh_Ys in bytes
    :vartype curve_type: int
    :cvar curve_type: Type of curve used (explicit, named, etc.)
    :vartype named_curve: int
    :cvar named_curve: TLS ID of named curve
    :vartype ecdh_Ys: bytearray
    :cvar ecdh_Ys: ECDH protocol encoded point key share
    :vartype signature: bytearray
    :cvar signature: signature performed over the parameters by server
    :vartype hashAlg: int
    :cvar hashAlg: id of hash algorithm used for signature
    :vartype signAlg: int
    :cvar signAlg: id of signature algorithm used for signature
    """

    def __init__(self, cipherSuite, version):
        """
        Initialise Server Key Exchange for reading or writing.

        :type cipherSuite: int
        :param cipherSuite: id of ciphersuite selected by server
        """
        HandshakeMsg.__init__(self, HandshakeType.server_key_exchange)
        self.cipherSuite = cipherSuite
        self.version = version
        self.srp_N = 0
        self.srp_N_len = None
        self.srp_g = 0
        self.srp_g_len = None
        self.srp_s = bytearray(0)
        self.srp_B = 0
        self.srp_B_len = None
        self.dh_p = 0
        self.dh_p_len = None
        self.dh_g = 0
        self.dh_g_len = None
        self.dh_Ys = 0
        self.dh_Ys_len = None
        self.curve_type = None
        self.named_curve = None
        self.ecdh_Ys = bytearray(0)
        self.signature = bytearray(0)
        self.hashAlg = 0
        self.signAlg = 0

    def __repr__(self):
        ret = 'ServerKeyExchange(cipherSuite=CipherSuite.{0}, version={1}'.format(CipherSuite.ietfNames[self.cipherSuite], self.version)
        if self.srp_N != 0:
            ret += ', srp_N={0}, srp_g={1}, srp_s={2!r}, srp_B={3}'.format(self.srp_N, self.srp_g, self.srp_s, self.srp_B)
        if self.dh_p != 0:
            ret += ', dh_p={0}, dh_g={1}, dh_Ys={2}'.format(self.dh_p, self.dh_g, self.dh_Ys)
        if self.signAlg != 0:
            ret += ', hashAlg={0}, signAlg={1}'.format(self.hashAlg, self.signAlg)
        if self.signature != bytearray(0):
            ret += ', signature={0!r}'.format(self.signature)
        ret += ')'
        return ret

    def createSRP(self, srp_N, srp_g, srp_s, srp_B):
        """Set SRP protocol parameters."""
        pass

    def createDH(self, dh_p, dh_g, dh_Ys):
        """Set FFDH protocol parameters."""
        pass

    def createECDH(self, curve_type, named_curve=None, point=None):
        """Set ECDH protocol parameters."""
        pass

    def parse(self, parser):
        """
        Deserialise message from :py:class:`Parser`.

        :type parser: Parser
        :param parser: parser to read data from
        """
        pass

    def writeParams(self):
        """
        Serialise the key exchange parameters.

        :rtype: bytearray
        """
        pass

    def write(self):
        """
        Serialise complete message.

        :rtype: bytearray
        """
        pass

    def hash(self, clientRandom, serverRandom):
        """
        Calculate hash of parameters to sign.

        :rtype: bytearray
        """
        pass

class ServerHelloDone(HandshakeMsg):

    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.server_hello_done)

    def __repr__(self):
        """Human readable representation of object."""
        return 'ServerHelloDone()'

class ClientKeyExchange(HandshakeMsg):
    """
    Handling of TLS Handshake protocol ClientKeyExchange message.

    :vartype cipherSuite: int
    :ivar cipherSuite: the cipher suite id used for the connection
    :vartype ~.version: tuple(int, int)
    :ivar ~.version: TLS protocol version used for the connection
    :vartype srp_A: int
    :ivar srp_A: SRP protocol client answer value
    :vartype dh_Yc: int
    :ivar dh_Yc: client Finite Field Diffie-Hellman protocol key share
    :vartype ecdh_Yc: bytearray
    :ivar ecdh_Yc: encoded curve coordinates
    :vartype encryptedPreMasterSecret: bytearray
    :ivar encryptedPreMasterSecret: client selected PremMaster secret encrypted
        with server public key (from certificate)
    """

    def __init__(self, cipherSuite, version=None):
        """
        Initialise ClientKeyExchange for reading or writing.

        :type cipherSuite: int
        :param cipherSuite: id of the ciphersuite selected by server
        :type version: tuple(int, int)
        :param version: protocol version selected by server
        """
        HandshakeMsg.__init__(self, HandshakeType.client_key_exchange)
        self.cipherSuite = cipherSuite
        self.version = version
        self.srp_A = 0
        self.dh_Yc = 0
        self.ecdh_Yc = bytearray(0)
        self.encryptedPreMasterSecret = bytearray(0)

    def createSRP(self, srp_A):
        """
        Set the SRP client answer.

        returns self

        :type srp_A: int
        :param srp_A: client SRP answer
        :rtype: ClientKeyExchange
        """
        pass

    def createRSA(self, encryptedPreMasterSecret):
        """
        Set the encrypted PreMaster Secret.

        returns self

        :type encryptedPreMasterSecret: bytearray
        :rtype: ClientKeyExchange
        """
        pass

    def createDH(self, dh_Yc):
        """
        Set the client FFDH key share.

        returns self

        :type dh_Yc: int
        :rtype: ClientKeyExchange
        """
        pass

    def createECDH(self, ecdh_Yc):
        """
        Set the client ECDH key share.

        returns self

        :type ecdh_Yc: bytearray
        :rtype: ClientKeyExchange
        """
        pass

    def parse(self, parser):
        """
        Deserialise the message from :py:class:`Parser`,

        returns self

        :type parser: Parser
        :rtype: ClientKeyExchange
        """
        pass

    def write(self):
        """
        Serialise the object.

        :rtype: bytearray
        """
        pass

class ClientMasterKey(HandshakeMsg):
    """
    Handling of SSLv2 CLIENT-MASTER-KEY message.

    :vartype cipher: int
    :ivar cipher: negotiated cipher

    :vartype clear_key: bytearray
    :ivar clear_key: the part of master secret key that is sent in clear for
        export cipher suites

    :vartype encrypted_key: bytearray
    :ivar encrypted_key: (part of) master secret encrypted using server key

    :vartype key_argument: bytearray
    :ivar key_argument: additional key argument for block ciphers
    """

    def __init__(self):
        super(ClientMasterKey, self).__init__(SSL2HandshakeType.client_master_key)
        self.cipher = 0
        self.clear_key = bytearray(0)
        self.encrypted_key = bytearray(0)
        self.key_argument = bytearray(0)

    def create(self, cipher, clear_key, encrypted_key, key_argument):
        """Set values of the CLIENT-MASTER-KEY object."""
        pass

    def write(self):
        """Serialise the object to on the wire data."""
        pass

    def parse(self, parser):
        """Deserialise object from on the wire data."""
        pass

class CertificateVerify(HandshakeMsg):
    """Serializer for TLS handshake protocol Certificate Verify message."""

    def __init__(self, version):
        """
        Create message.

        :param version: TLS protocol version in use
        """
        HandshakeMsg.__init__(self, HandshakeType.certificate_verify)
        self.version = version
        self.signatureAlgorithm = None
        self.signature = bytearray(0)

    def create(self, signature, signatureAlgorithm=None):
        """
        Provide data for serialisation of message.

        :param signature: signature carried in the message
        :param signatureAlgorithm: signature algorithm used to make the
            signature (TLSv1.2 only)
        """
        pass

    def parse(self, parser):
        """
        Deserialize message from parser.

        :param parser: parser with data to read
        """
        pass

    def write(self):
        """
        Serialize the data to bytearray.

        :rtype: bytearray
        """
        pass

class ChangeCipherSpec(object):

    def __init__(self):
        self.contentType = ContentType.change_cipher_spec
        self.type = 1

class NextProtocol(HandshakeMsg):

    def __init__(self):
        HandshakeMsg.__init__(self, HandshakeType.next_protocol)
        self.next_proto = None

class Finished(HandshakeMsg):

    def __init__(self, version, hash_length=None):
        HandshakeMsg.__init__(self, HandshakeType.finished)
        self.version = version
        self.verify_data = bytearray(0)
        self.hash_length = hash_length

class EncryptedExtensions(HelloMessage):
    """Handling of the TLS1.3 Encrypted Extensions message."""

    def __init__(self):
        super(EncryptedExtensions, self).__init__(HandshakeType.encrypted_extensions)

    def create(self, extensions):
        """Set the extensions in the message."""
        pass

    def parse(self, parser):
        """Parse the extensions from on the wire data."""
        pass

    def write(self):
        """
        Serialise the message to on the wire data.

        :rtype: bytearray
        """
        pass

class NewSessionTicket(HelloMessage):
    """Handling of the TLS1.3 New Session Ticket message."""

    def __init__(self):
        """Create New Session Ticket object."""
        super(NewSessionTicket, self).__init__(HandshakeType.new_session_ticket)
        self.ticket_lifetime = 0
        self.ticket_age_add = 0
        self.ticket_nonce = bytearray(0)
        self.ticket = bytearray(0)
        self.extensions = []
        self.time = None

    def create(self, ticket_lifetime, ticket_age_add, ticket_nonce, ticket, extensions):
        """Initialise a New Session Ticket."""
        pass

    def write(self):
        """
        Serialise the message to on the wire data.

        :rtype: bytearray
        """
        pass

    def parse(self, parser):
        """Parse the object from on the wire data."""
        pass

class NewSessionTicket1_0(HelloMessage):
    """Handling of the TLS1.0-TLS1.2 NewSessionTicket message."""

    def __init__(self):
        """Create New Session Ticket object."""
        super(NewSessionTicket1_0, self).__init__(HandshakeType.new_session_ticket)
        self.ticket_lifetime = 0
        self.ticket = bytearray(0)

    def create(self, ticket_lifetime, ticket):
        """Initialise a New Session Ticket."""
        pass

    def write(self):
        """
        Serialise the message to on the wire data.

        :rtype: bytearray
        """
        pass

    def parse(self, parser):
        """Parse the object from on the wire data."""
        pass

class SessionTicketPayload(object):
    """Serialisation and deserialisation of server state for resumption.

    This is the internal (meant to be encrypted) representation of server
    state that is sent to the client in the NewSessionTicket message.

    :ivar int ~.version: implementation detail for forward compatibility
    :ivar bytearray master_secret: master secret for TLS 1.2-, resumption
        master secret for TLS 1.3

    :ivar tuple protocol_version: version of protocol that was previously
        negotiated in this session

    :ivar int cipher_suite: numerical ID of ciphersuite that was negotiated
        previously

    :ivar bytearray nonce: nonce for TLS 1.3 KDF

    :ivar int creation_time: Unix time in seconds when was the ticket created
    :ivar X509CertChain client_cert_chain: Client X509 Certificate Chain
    :ivar bool encrypt_then_mac: The session used the encrypt_then_mac
        extension
    :ivar bool extended_master_secret: The session used the
        extended_master_secret extension
    """

    def __init__(self):
        """Create instance of the object."""
        self.version = 0
        self.master_secret = bytearray()
        self.protocol_version = bytearray()
        self.cipher_suite = 0
        self.creation_time = 0
        self.nonce = bytearray()
        self._cert_chain = None
        self.encrypt_then_mac = False
        self.extended_master_secret = False
        self.server_name = bytearray()

    @property
    def client_cert_chain(self):
        """Getter for the client_cert_chain property."""
        pass

    @client_cert_chain.setter
    def client_cert_chain(self, client_cert_chain):
        """Setter for the cert_chain property."""
        pass

    def create(self, master_secret, protocol_version, cipher_suite, creation_time, nonce=bytearray(), client_cert_chain=None, encrypt_then_mac=False, extended_master_secret=False, server_name=bytearray()):
        """Initialise the object with cryptographic data."""
        pass

class SSL2Finished(HandshakeMsg):
    """Handling of the SSL2 FINISHED messages."""

    def __init__(self, msg_type):
        super(SSL2Finished, self).__init__(msg_type)
        self.verify_data = bytearray(0)

    def create(self, verify_data):
        """Set the message payload."""
        pass

    def parse(self, parser):
        """Deserialise the message from on the wire data."""
        pass

    def write(self):
        """Serialise the message to on the wire data."""
        pass

class ClientFinished(SSL2Finished):
    """
    Handling of SSLv2 CLIENT-FINISHED message.

    :vartype verify_data: bytearray
    :ivar verify_data: payload of the message, should be the CONNECTION-ID
    """

    def __init__(self):
        super(ClientFinished, self).__init__(SSL2HandshakeType.client_finished)

class ServerFinished(SSL2Finished):
    """
    Handling of SSLv2 SERVER-FINISHED message.

    :vartype verify_data: bytearray
    :ivar verify_data: payload of the message, should be SESSION-ID
    """

    def __init__(self):
        super(ServerFinished, self).__init__(SSL2HandshakeType.server_finished)

class CertificateStatus(HandshakeMsg):
    """
    Handling of the CertificateStatus message from RFC 6066.

    Handling of the handshake protocol message that includes the OCSP staple.

    :vartype status_type: int
    :ivar status_type: type of response returned

    :vartype ocsp: bytearray
    :ivar ocsp: OCSPResponse from RFC 2560
    """

    def __init__(self):
        """Create the objet, set its type."""
        super(CertificateStatus, self).__init__(HandshakeType.certificate_status)
        self.status_type = None
        self.ocsp = bytearray()

    def create(self, status_type, ocsp):
        """Set up message payload."""
        pass

    def parse(self, parser):
        """Deserialise the message from one the wire data."""
        pass

    def write(self):
        """Serialise the message."""
        pass

class ApplicationData(object):

    def __init__(self):
        self.contentType = ContentType.application_data
        self.bytes = bytearray(0)

class Heartbeat(object):
    """
    Handling Heartbeat messages from RFC 6520

    :type message_type: int
    :ivar message_type: type of message (response or request)

    :type payload: bytearray
    :ivar payload: payload

    :type padding: bytearray
    :ivar padding: random padding of selected length
    """

    def __init__(self):
        self.contentType = ContentType.heartbeat
        self.message_type = 0
        self.payload = bytearray(0)
        self.padding = bytearray(0)

    def create(self, message_type, payload, padding_length):
        """Create heartbeat request or response with selected parameters"""
        pass

    def create_response(self):
        """Creates heartbeat response based on request."""
        pass

    def parse(self, p):
        """
        Deserialize heartbeat message from parser.

        We are reading only message type and payload, ignoring
        leftover bytes (padding).
        """
        pass

    def write(self):
        """Serialise heartbeat message."""
        pass

    @property
    def _message_type(self):
        """Format heartbeat message to human readable representation."""
        pass

    def __str__(self):
        """Return human readable representation of heartbeat message."""
        return 'heartbeat {0}'.format(self._message_type)

class KeyUpdate(HandshakeMsg):
    """
    Handling KeyUpdate message from RFC 8446

    :vartype message_type: int
    :ivar message_type: type of message (update_not_requested or
                                         update_requested)
    """

    def __init__(self):
        super(KeyUpdate, self).__init__(HandshakeType.key_update)
        self.message_type = 0

    def create(self, message_type):
        """Create KeyUpdate message with selected parameter."""
        pass

    def parse(self, p):
        """Deserialize keyupdate message from parser."""
        pass

    def write(self):
        """Serialise keyupdate message."""
        pass