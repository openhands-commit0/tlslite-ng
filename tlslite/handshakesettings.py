"""Class for setting handshake parameters."""
from .constants import CertificateType
from .utils import cryptomath
from .utils import cipherfactory
from .utils.compat import ecdsaAllCurves, int_types
CIPHER_NAMES = ['chacha20-poly1305', 'aes256gcm', 'aes128gcm', 'aes256ccm', 'aes128ccm', 'aes256', 'aes128', '3des']
ALL_CIPHER_NAMES = CIPHER_NAMES + ['chacha20-poly1305_draft00', 'aes128ccm_8', 'aes256ccm_8', 'rc4', 'null']
MAC_NAMES = ['sha', 'sha256', 'sha384', 'aead']
ALL_MAC_NAMES = MAC_NAMES + ['md5']
KEY_EXCHANGE_NAMES = ['ecdhe_ecdsa', 'rsa', 'dhe_rsa', 'ecdhe_rsa', 'srp_sha', 'srp_sha_rsa', 'ecdh_anon', 'dh_anon', 'dhe_dsa']
CIPHER_IMPLEMENTATIONS = ['openssl', 'pycrypto', 'python']
CERTIFICATE_TYPES = ['x509']
RSA_SIGNATURE_HASHES = ['sha512', 'sha384', 'sha256', 'sha224', 'sha1']
DSA_SIGNATURE_HASHES = ['sha512', 'sha384', 'sha256', 'sha224', 'sha1']
ECDSA_SIGNATURE_HASHES = ['sha512', 'sha384', 'sha256', 'sha224', 'sha1']
ALL_RSA_SIGNATURE_HASHES = RSA_SIGNATURE_HASHES + ['md5']
SIGNATURE_SCHEMES = ['Ed25519', 'Ed448']
RSA_SCHEMES = ['pss', 'pkcs1']
CURVE_NAMES = ['x25519', 'x448', 'secp384r1', 'secp256r1', 'secp521r1']
ALL_CURVE_NAMES = CURVE_NAMES + ['secp256k1', 'brainpoolP512r1', 'brainpoolP384r1', 'brainpoolP256r1']
if ecdsaAllCurves:
    ALL_CURVE_NAMES += ['secp224r1', 'secp192r1']
ALL_DH_GROUP_NAMES = ['ffdhe2048', 'ffdhe3072', 'ffdhe4096', 'ffdhe6144', 'ffdhe8192']
CURVE_ALIASES = {'secp256r1': ('NIST256p', 'prime256v1', 'P-256'), 'secp384r1': ('NIST384p', 'P-384'), 'secp521r1': ('NIST521p', 'P-521'), 'secp256k1': ('SECP256k1',), 'secp192r1': ('NIST192p', 'P-192'), 'secp224r1': ('NIST224p', 'P-224'), 'brainpoolP256r1': ('BRAINPOOLP256r1',), 'brainpoolP384r1': ('BRAINPOOLP384r1',), 'brainpoolP512r1': ('BRAINPOOLP512r1',)}
TLS13_PERMITTED_GROUPS = ['secp256r1', 'secp384r1', 'secp521r1', 'x25519', 'x448', 'ffdhe2048', 'ffdhe3072', 'ffdhe4096', 'ffdhe6144', 'ffdhe8192']
KNOWN_VERSIONS = ((3, 0), (3, 1), (3, 2), (3, 3), (3, 4))
TICKET_CIPHERS = ['chacha20-poly1305', 'aes256gcm', 'aes128gcm', 'aes128ccm', 'aes128ccm_8', 'aes256ccm', 'aes256ccm_8']
PSK_MODES = ['psk_dhe_ke', 'psk_ke']

class Keypair(object):
    """
    Key, certificate and related data.

    Stores also certificate associate data like OCSPs and transparency info.
    TODO: add the above

    First certificate in certificates needs to match key, remaining should
    build a trust path to a root CA.

    :vartype key: RSAKey or ECDSAKey
    :ivar key: private key

    :vartype certificates: list(X509)
    :ivar certificates: the certificates to send to peer if the key is selected
        for use. The first one MUST include the public key of the ``key``
    """

    def __init__(self, key=None, certificates=tuple()):
        self.key = key
        self.certificates = certificates

    def validate(self):
        """Sanity check the keypair."""
        pass

class VirtualHost(object):
    """
    Configuration of keys and certs for a single virual server.

    This class encapsulates keys and certificates for hosts specified by
    server_name (SNI) and ALPN extensions.

    TODO: support SRP as alternative to certificates
    TODO: support PSK as alternative to certificates

    :vartype keys: list(Keypair)
    :ivar keys: List of certificates and keys to be used in this
        virtual host. First keypair able to server ClientHello will be used.

    :vartype hostnames: set(bytes)
    :ivar hostnames: all the hostnames that server supports
        please use :py:meth:`matches_hostname` to verify if the VirtualHost
        can serve a request to a given hostname as that allows wildcard hosts
        that always reply True.

    :vartype trust_anchors: list(X509)
    :ivar trust_anchors: list of CA certificates supported for client
        certificate authentication, sent in CertificateRequest

    :ivar list(bytes) app_protocols: all the application protocols that the
        server supports (for ALPN)
    """

    def __init__(self):
        """Set up default configuration."""
        self.keys = []
        self.hostnames = set()
        self.trust_anchors = []
        self.app_protocols = []

    def matches_hostname(self, hostname):
        """Checks if the virtual host can serve hostname"""
        pass

    def validate(self):
        """Sanity check the settings"""
        pass

class HandshakeSettings(object):
    """
    This class encapsulates various parameters that can be used with
    a TLS handshake.

    :vartype minKeySize: int
    :ivar minKeySize: The minimum bit length for asymmetric keys.

        If the other party tries to use SRP, RSA, DSA, or Diffie-Hellman
        parameters smaller than this length, an alert will be
        signalled.  The default is 1023.


    :vartype maxKeySize: int
    :ivar maxKeySize: The maximum bit length for asymmetric keys.

        If the other party tries to use SRP, RSA, DSA, or Diffie-Hellman
        parameters larger than this length, an alert will be signalled.
        The default is 8193.

    :vartype cipherNames: list(str)
    :ivar cipherNames: The allowed ciphers.

        The allowed values in this list are 'chacha20-poly1305', 'aes256gcm',
        'aes128gcm', 'aes256', 'aes128', '3des', 'chacha20-poly1305_draft00',
        'null' and
        'rc4'.  If these settings are used with a client handshake, they
        determine the order of the ciphersuites offered in the ClientHello
        message.

        If these settings are used with a server handshake, the server will
        choose whichever ciphersuite matches the earliest entry in this
        list.

        The default value is list that excludes 'rc4', 'null' and
        'chacha20-poly1305_draft00'.

    :vartype macNames: list(str)
    :ivar macNames: The allowed MAC algorithms.

        The allowed values in this list are 'sha384', 'sha256', 'aead', 'sha'
        and 'md5'.

        The default value is list that excludes 'md5'.

    :vartype certificateTypes: list(str)
    :ivar certificateTypes: The allowed certificate types.

        The only allowed certificate type is 'x509'.  This list is only used
        with a
        client handshake.  The client will advertise to the server which
        certificate
        types are supported, and will check that the server uses one of the
        appropriate types.


    :vartype minVersion: tuple
    :ivar minVersion: The minimum allowed SSL/TLS version.

        This variable can be set to (3, 0) for SSL 3.0, (3, 1) for TLS 1.0,
        (3, 2) for
        TLS 1.1, or (3, 3) for TLS 1.2.  If the other party wishes to use a
        lower
        version, a protocol_version alert will be signalled.  The default is
        (3, 1).

    :vartype maxVersion: tuple
    :ivar maxVersion: The maximum allowed SSL/TLS version.

        This variable can be set to (3, 0) for SSL 3.0, (3, 1) for TLS 1.0,
        (3, 2) for TLS 1.1, or (3, 3) for TLS 1.2.  If the other party wishes
        to use a
        higher version, a protocol_version alert will be signalled.  The
        default is (3, 3).

        .. warning:: Some servers may (improperly) reject clients which offer
            support
            for TLS 1.1 or higher.  In this case, try lowering maxVersion to
            (3, 1).

    :vartype useExperimentalTackExtension: bool
    :ivar useExperimentalTackExtension: Whether to enabled TACK support.

        Note that TACK support is not standardized by IETF and uses a temporary
        TLS Extension number, so should NOT be used in production software.

    :vartype sendFallbackSCSV: bool
    :ivar sendFallbackSCSV: Whether to, as a client, send FALLBACK_SCSV.

    :vartype rsaSigHashes: list(str)
    :ivar rsaSigHashes: List of hashes supported (and advertised as such) for
        TLS 1.2 signatures over Server Key Exchange or Certificate Verify with
        RSA signature algorithm.

        The list is sorted from most wanted to least wanted algorithm.

        The allowed hashes are: "md5", "sha1", "sha224", "sha256",
        "sha384" and "sha512". The default list does not include md5.

    :vartype dsaSigHashes: list(str)
    :ivar dsaSigHashes: List of hashes supported (and advertised as such) for
        TLS 1.2 signatures over Server Key Exchange or Certificate Verify with
        DSA signature algorithm.

        The list is sorted from most wanted to least wanted algorithm.

        The allowed hashes are: "sha1", "sha224", "sha256",
        "sha384" and "sha512".

    :vartype ecdsaSigHashes: list(str)
    :ivar ecdsaSigHashes: List of hashes supported (and advertised as such) for
        TLS 1.2 signatures over Server Key Exchange or Certificate Verify with
        ECDSA signature algorithm.

        The list is sorted from most wanted to least wanted algorithm.

        The allowed hashes are: "sha1", "sha224", "sha256",
        "sha384" and "sha512".

    "vartype more_sig_schemes: list(str)
    :ivar more_sig_schemes: List of additional signatures schemes (ones
        that don't use RSA-PKCS#1 v1.5, RSA-PSS, DSA, or ECDSA) to advertise
        as supported.
        Currently supported are: "Ed25519", and "Ed448".

    :vartype eccCurves: list(str)
    :ivar eccCurves: List of named curves that are to be advertised as
        supported in supported_groups extension.

    :vartype useEncryptThenMAC: bool
    :ivar useEncryptThenMAC: whether to support the encrypt then MAC extension
        from RFC 7366. True by default.

    :vartype useExtendedMasterSecret: bool
    :ivar useExtendedMasterSecret: whether to support the extended master
        secret calculation from RFC 7627. True by default.

    :vartype requireExtendedMasterSecret: bool
    :ivar requireExtendedMasterSecret: whether to require negotiation of
        extended master secret calculation for successful connection. Requires
        useExtendedMasterSecret to be set to true. False by default.

    :vartype defaultCurve: str
    :ivar defaultCurve: curve that will be used by server in case the client
        did not advertise support for any curves. It does not have to be the
        first curve for eccCurves and may be distinct from curves from that
        list.

    :vartype keyShares: list(str)
    :ivar keyShares: list of TLS 1.3 key shares to include in Client Hello

    :vartype padding_cb: func
    :ivar padding_cb: Callback to function computing number of padding bytes
        for TLS 1.3. Signature is cb_func(msg_size, content_type, max_size).

    :vartype pskConfigs: list(tuple(bytearray, bytearray, bytearray))
    :ivar pskConfigs: list of tuples, first element of the tuple is the
        human readable, UTF-8 encoded, "identity" of the associated secret
        (bytearray, can be empty for TLS 1.2 and earlier), second element is
        the binary secret (bytearray), third is an optional parameter
        specifying the PRF hash to be used in TLS 1.3 (``sha256`` or
        ``sha384``, with ``sha256`` being the default)

    :vartype ticketKeys: list(bytearray)
    :ivar ticketKeys: keys to be used for encrypting and decrypting session
        tickets. First entry is the encryption key for new tickets and the
        default decryption key, subsequent entries are the fallback keys
        allowing for key rollover. The keys need to be of size appropriate
        for a selected cipher in ticketCipher, 32 bytes for 'aes256gcm' and
        'chacha20-poly1305', 16 bytes for 'aes128-gcm'.
        New keys should be generated regularly and replace old ones. Key use
        time should generally not be longer than 24h and key life-time should
        not be longer than 48h.
        Leave empty to disable session ticket support on server side.

    :vartype ticketCipher: str
    :ivar ticketCipher: name of the cipher used for encrypting the session
        tickets. 'aes256gcm' by default, 'aes128gcm' or 'chacha20-poly1305'
        alternatively.

    :vartype ticketLifetime: int
    :ivar ticketLifetime: maximum allowed lifetime of ticket encryption key,
        in seconds. 1 day by default

    :vartype ticket_count: int
    :ivar ticket_count: number of tickets the server will send to the client
        after establishing the connection in TLS 1.3. If a positive integer,
        it enabled support for ticket based resumption in TLS 1.2 and earlier.

    :vartype psk_modes: list(str)
    :ivar psk_modes: acceptable modes for the PSK key exchange in TLS 1.3

    :ivar int max_early_data: maximum number of bytes acceptable for 0-RTT
        early_data processing. In other words, how many bytes will the server
        try to process, but ignore, in case the Client Hello includes
        early_data extension.

    :vartype use_heartbeat_extension: bool
    :ivar use_heartbeat_extension: whether to support heartbeat extension from
        RFC 6520. True by default.

    :vartype heartbeat_response_callback: func
    :ivar heartbeat_response_callback: Callback to function when Heartbeat
        response is received.

    :vartype ~.record_size_limit: int
    :ivar ~.record_size_limit: maximum size of records we are willing to process
        (value advertised to the other side). It must not be larger than
        2**14+1 (the maximum for TLS 1.3) and will be reduced to 2**14 if TLS
        1.2 or lower is the highest enabled version. Must not be set to values
        smaller than 64. Set to None to disable support for the extension.
        See also: RFC 8449.

    :vartype keyExchangeNames: list
    :ivar keyExchangeNames: Enabled key exchange types for the connection,
        influences selected cipher suites.
    """

    def _init_key_settings(self):
        """Create default variables for key-related settings."""
        self.minKeySize = 1023
        self.maxKeySize = 8193
        self.rsaSigHashes = list(RSA_SIGNATURE_HASHES)
        self.dsaSigHashes = list(DSA_SIGNATURE_HASHES)
        self.ecdsaSigHashes = list(ECDSA_SIGNATURE_HASHES)
        self.more_sig_schemes = list(SIGNATURE_SCHEMES)
        self.rsa_schemes = list(RSA_SCHEMES)
        self.eccCurves = list(CURVE_NAMES)
        self.dhGroups = list(ALL_DH_GROUP_NAMES)
        self.defaultCurve = "secp256r1"
        self.keyShares = ["secp256r1", "x25519"]
        self.certificateTypes = list(CERTIFICATE_TYPES)

    def _init_misc_extensions(self):
        """Default variables for assorted extensions."""
        self.useExtendedMasterSecret = True
        self.requireExtendedMasterSecret = False
        self.useEncryptThenMAC = True
        self.useExperimentalTackExtension = False
        self.sendFallbackSCSV = False
        self.use_heartbeat_extension = True
        self.heartbeat_response_callback = None
        self.record_size_limit = None
        self.padding_cb = None
        self.pskConfigs = []
        self.psk_modes = list(PSK_MODES)
        self.max_early_data = 0
        self.ticketKeys = []
        self.ticketCipher = "aes256gcm"
        self.ticketLifetime = 24 * 60 * 60  # 1 day
        self.ticket_count = 1

    def __init__(self):
        """Initialise default values for settings."""
        self._init_key_settings()
        self._init_misc_extensions()
        self.minVersion = (3, 1)
        self.maxVersion = (3, 4)
        self.versions = [(3, 4), (3, 3), (3, 2), (3, 1)]
        self.cipherNames = list(CIPHER_NAMES)
        self.macNames = list(MAC_NAMES)
        self.keyExchangeNames = list(KEY_EXCHANGE_NAMES)
        self.cipherImplementations = list(CIPHER_IMPLEMENTATIONS)

    @staticmethod
    def _sanityCheckKeySizes(other):
        """Check if key size limits are sane"""
        if other.minKeySize < 512:
            raise ValueError("minKeySize too small")
        if other.minKeySize > 16384:
            raise ValueError("minKeySize too large")
        if other.maxKeySize < 512:
            raise ValueError("maxKeySize too small")
        if other.maxKeySize > 16384:
            raise ValueError("maxKeySize too large")
        if other.maxKeySize < other.minKeySize:
            raise ValueError("maxKeySize smaller than minKeySize")

    @staticmethod
    def _not_matching(values, sieve):
        """Return list of items from values that are not in sieve."""
        return [val for val in values if val not in sieve]

    @staticmethod
    def _sanityCheckCipherSettings(other):
        """Check if specified cipher settings are known."""
        not_matching = HandshakeSettings._not_matching(other.cipherNames,
                                                     ALL_CIPHER_NAMES)
        if not_matching:
            raise ValueError("Unknown cipher name: {0}".format(not_matching))

        not_matching = HandshakeSettings._not_matching(other.macNames,
                                                     ALL_MAC_NAMES)
        if not_matching:
            raise ValueError("Unknown MAC name: {0}".format(not_matching))

        not_matching = HandshakeSettings._not_matching(
            other.cipherImplementations, CIPHER_IMPLEMENTATIONS)
        if not_matching:
            raise ValueError("Unknown cipher implementation: {0}"
                           .format(not_matching))

    @staticmethod
    def _sanityCheckECDHSettings(other):
        """Check ECDHE settings if they are sane."""
        not_matching = HandshakeSettings._not_matching(other.eccCurves,
                                                     ALL_CURVE_NAMES)
        if not_matching:
            raise ValueError("Unknown ECC curve name: {0}".format(not_matching))

        if other.defaultCurve not in ALL_CURVE_NAMES:
            raise ValueError("Unknown default ECC curve name: {0}"
                           .format(other.defaultCurve))

    @staticmethod
    def _sanityCheckDHSettings(other):
        """Check if (EC)DHE settings are sane."""
        not_matching = HandshakeSettings._not_matching(other.dhGroups,
                                                     ALL_DH_GROUP_NAMES)
        if not_matching:
            raise ValueError("Unknown DH group name: {0}".format(not_matching))

    @staticmethod
    def _sanityCheckPrimitivesNames(other):
        """Check if specified cryptographic primitive names are known"""
        not_matching = HandshakeSettings._not_matching(other.rsaSigHashes,
                                                     ALL_RSA_SIGNATURE_HASHES)
        if not_matching:
            raise ValueError("Unknown RSA signature hash: {0}"
                           .format(not_matching))

        not_matching = HandshakeSettings._not_matching(other.dsaSigHashes,
                                                     DSA_SIGNATURE_HASHES)
        if not_matching:
            raise ValueError("Unknown DSA signature hash: {0}"
                           .format(not_matching))

        not_matching = HandshakeSettings._not_matching(other.ecdsaSigHashes,
                                                     ECDSA_SIGNATURE_HASHES)
        if not_matching:
            raise ValueError("Unknown ECDSA signature hash: {0}"
                           .format(not_matching))

        not_matching = HandshakeSettings._not_matching(other.more_sig_schemes,
                                                     SIGNATURE_SCHEMES)
        if not_matching:
            raise ValueError("Unknown signature scheme: {0}"
                           .format(not_matching))

        not_matching = HandshakeSettings._not_matching(other.rsa_schemes,
                                                     RSA_SCHEMES)
        if not_matching:
            raise ValueError("Unknown RSA scheme: {0}"
                           .format(not_matching))

    @staticmethod
    def _sanityCheckProtocolVersions(other):
        """Check if set protocol version are sane"""
        if other.minVersion > other.maxVersion:
            raise ValueError("Versions set incorrectly")
        if other.minVersion not in KNOWN_VERSIONS:
            raise ValueError("Unknown minimum protocol version")
        if other.maxVersion not in KNOWN_VERSIONS:
            raise ValueError("Unknown maximum protocol version")

    @staticmethod
    def _sanityCheckEMSExtension(other):
        """Check if settings for EMS are sane."""
        if other.requireExtendedMasterSecret and \
                not other.useExtendedMasterSecret:
            raise ValueError("Require Extended Master Secret but don't use it")

    @staticmethod
    def _sanityCheckExtensions(other):
        """Check if set extension settings are sane"""
        if other.record_size_limit is not None:
            if not 64 <= other.record_size_limit <= 2**14+1:
                raise ValueError("Record size limit must be between 64 and 16385")

    @staticmethod
    def _not_allowed_len(values, sieve):
        """Return True if length of any item in values is not in sieve."""
        return any(len(i) not in sieve for i in values)

    @staticmethod
    def _sanityCheckPsks(other):
        """Check if the set PSKs are sane."""
        if other.psk_modes:
            not_matching = HandshakeSettings._not_matching(other.psk_modes,
                                                         PSK_MODES)
            if not_matching:
                raise ValueError("Unknown PSK mode: {0}".format(not_matching))

        if not all(isinstance(i, (bytes, bytearray)) for i in other.pskConfigs):
            raise ValueError("PSK identity must be a bytes-like object")

    @staticmethod
    def _sanityCheckTicketSettings(other):
        """Check if the session ticket settings are sane."""
        if other.ticketCipher not in TICKET_CIPHERS:
            raise ValueError("Unknown ticket cipher")

        if other.ticketLifetime < 0:
            raise ValueError("Ticket lifetime must be a positive integer")

        if other.ticket_count < 0:
            raise ValueError("Ticket count must be a positive integer")

    def _copy_cipher_settings(self, other):
        """Copy values related to cipher selection."""
        other.cipherNames = self.cipherNames
        other.macNames = self.macNames
        other.keyExchangeNames = self.keyExchangeNames
        other.cipherImplementations = self.cipherImplementations
        other.minVersion = self.minVersion
        other.maxVersion = self.maxVersion
        other.versions = self.versions

    def _copy_extension_settings(self, other):
        """Copy values of settings related to extensions."""
        other.useExtendedMasterSecret = self.useExtendedMasterSecret
        other.requireExtendedMasterSecret = self.requireExtendedMasterSecret
        other.useEncryptThenMAC = self.useEncryptThenMAC
        other.useExperimentalTackExtension = self.useExperimentalTackExtension
        other.sendFallbackSCSV = self.sendFallbackSCSV
        other.use_heartbeat_extension = self.use_heartbeat_extension
        other.heartbeat_response_callback = self.heartbeat_response_callback
        other.record_size_limit = self.record_size_limit
        other.padding_cb = self.padding_cb
        other.pskConfigs = self.pskConfigs
        other.psk_modes = self.psk_modes
        other.max_early_data = self.max_early_data
        other.ticketKeys = self.ticketKeys
        other.ticketCipher = self.ticketCipher
        other.ticketLifetime = self.ticketLifetime
        other.ticket_count = self.ticket_count

    @staticmethod
    def _remove_all_matches(values, needle):
        """Remove all instances of needle from values."""
        while needle in values:
            values.remove(needle)

    def getCertificateTypes(self):
        """Get list of certificate types as IDs."""
        ret = []
        if "x509" in self.certificateTypes:
            ret.append(CertificateType.x509)
        return ret

    def validate(self):
        """
        Validate the settings, filter out unsupported ciphersuites and return
        a copy of object.

        This method checks if the settings are consistent and if they can be
        used for a connection. It checks if all selected algorithms are
        supported.

        :rtype: HandshakeSettings
        :returns: a copy of self with all settings validated
        :raises ValueError: when settings are invalid, inconsistent or unsupported
        """
        other = HandshakeSettings()

        # Copy values
        other.minKeySize = self.minKeySize
        other.maxKeySize = self.maxKeySize
        other.cipherNames = self.cipherNames
        other.macNames = self.macNames
        other.keyExchangeNames = self.keyExchangeNames
        other.cipherImplementations = self.cipherImplementations
        other.rsaSigHashes = self.rsaSigHashes
        other.dsaSigHashes = self.dsaSigHashes
        other.ecdsaSigHashes = self.ecdsaSigHashes
        other.more_sig_schemes = self.more_sig_schemes
        other.rsa_schemes = self.rsa_schemes
        other.eccCurves = self.eccCurves
        other.dhGroups = self.dhGroups
        other.defaultCurve = self.defaultCurve
        other.keyShares = self.keyShares
        other.certificateTypes = self.certificateTypes
        other.minVersion = self.minVersion
        other.maxVersion = self.maxVersion
        other.versions = self.versions
        other.useExtendedMasterSecret = self.useExtendedMasterSecret
        other.requireExtendedMasterSecret = self.requireExtendedMasterSecret
        other.useEncryptThenMAC = self.useEncryptThenMAC
        other.useExperimentalTackExtension = self.useExperimentalTackExtension
        other.sendFallbackSCSV = self.sendFallbackSCSV
        other.use_heartbeat_extension = self.use_heartbeat_extension
        other.heartbeat_response_callback = self.heartbeat_response_callback
        other.record_size_limit = self.record_size_limit
        other.padding_cb = self.padding_cb
        other.pskConfigs = self.pskConfigs
        other.psk_modes = self.psk_modes
        other.max_early_data = self.max_early_data
        other.ticketKeys = self.ticketKeys
        other.ticketCipher = self.ticketCipher
        other.ticketLifetime = self.ticketLifetime
        other.ticket_count = self.ticket_count

        # Perform sanity checks
        self._sanityCheckKeySizes(other)
        self._sanityCheckCipherSettings(other)
        self._sanityCheckECDHSettings(other)
        self._sanityCheckDHSettings(other)
        self._sanityCheckPrimitivesNames(other)
        self._sanityCheckProtocolVersions(other)
        self._sanityCheckEMSExtension(other)
        self._sanityCheckExtensions(other)
        self._sanityCheckPsks(other)
        self._sanityCheckTicketSettings(other)

        return other

    def _sanity_check_ciphers(self, other):
        """Remove unsupported ciphers in current configuration."""
        if not other.cipherNames:
            raise ValueError("No cipher names specified")

        if not other.macNames:
            raise ValueError("No MAC names specified")

        if not other.keyExchangeNames:
            raise ValueError("No key exchange algorithms specified")

        if not other.cipherImplementations:
            raise ValueError("No cipher implementations specified")

        # Remove ciphers that are not supported
        for cipher in other.cipherNames[:]:
            if cipher not in ALL_CIPHER_NAMES:
                other.cipherNames.remove(cipher)

        # Remove MACs that are not supported
        for mac in other.macNames[:]:
            if mac not in ALL_MAC_NAMES:
                other.macNames.remove(mac)

        # Remove key exchange algorithms that are not supported
        for kex in other.keyExchangeNames[:]:
            if kex not in KEY_EXCHANGE_NAMES:
                other.keyExchangeNames.remove(kex)

        # Remove cipher implementations that are not supported
        for impl in other.cipherImplementations[:]:
            if impl not in CIPHER_IMPLEMENTATIONS:
                other.cipherImplementations.remove(impl)

        # Check if any ciphers remain
        if not other.cipherNames:
            raise ValueError("No supported cipher names")

        # Check if any MACs remain
        if not other.macNames:
            raise ValueError("No supported MAC names")

        # Check if any key exchange algorithms remain
        if not other.keyExchangeNames:
            raise ValueError("No supported key exchange algorithms")

        # Check if any cipher implementations remain
        if not other.cipherImplementations:
            raise ValueError("No supported cipher implementations")
    def _sanity_check_implementations(self, other):
        """Remove all backends that are not loaded."""
        if not cryptomath.m2cryptoLoaded:
            self._remove_all_matches(other.cipherImplementations, "openssl")
        if not cryptomath.pycryptoLoaded:
            self._remove_all_matches(other.cipherImplementations, "pycrypto")

        if not other.cipherImplementations:
            raise ValueError("No supported cipher implementations")
    def _copy_key_settings(self, other):
        """Copy key-related settings."""
        other.minKeySize = self.minKeySize
        other.maxKeySize = self.maxKeySize
        other.rsaSigHashes = self.rsaSigHashes
        other.dsaSigHashes = self.dsaSigHashes
        other.ecdsaSigHashes = self.ecdsaSigHashes
        other.more_sig_schemes = self.more_sig_schemes
        other.rsa_schemes = self.rsa_schemes
        other.eccCurves = self.eccCurves
        other.dhGroups = self.dhGroups
        other.defaultCurve = self.defaultCurve
        other.keyShares = self.keyShares
        other.certificateTypes = self.certificateTypes
        pass

    def validate(self):
        """
        Validate the settings, filter out unsupported ciphersuites and return
        a copy of object. Does not modify the original object.

        :rtype: HandshakeSettings
        :returns: a self-consistent copy of settings
        :raises ValueError: when settings are invalid, insecure or unsupported.
        """
        pass

    def getCertificateTypes(self):
        """Get list of certificate types as IDs"""
        pass