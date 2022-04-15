from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

class MTPMessage:
    """ 
    A class to represent SiFT Message Transfer Protocol messages
    
    ...

    Attributes
    ----------
    ver : bytes
        A 2-byte version number field, where the first byte is the major version (i.e., 1 in case of v1.0) and the second byte is the minor version (i.e., 0 in case of v1.0).
    typ : bytes
        A 2-byte message type field that specifies the type of the payload in the message.
    len : bytes
        A 2-byte message length field that contains the length of the entire message (including the header) in bytes (using big endian byte order).
    sqn : bytes
        A 2-byte message sequence number field that contains the sequence number of this message (using big endian byte order).
    rnd : bytes
        A 6-byte random field that contains freshly generated random bytes.
    rsv : bytes
        A 2-byte reserved field which is not used in this version of the protocol (reserved for future versions). Value should be set to 00 00.
    """
    
    def __init__(self, ver: bytes, typ: bytes, len: bytes, sqn: bytes, rnd: bytes, rsv: bytes) -> None:
        if (len(ver) is not 2 or 
            len(typ) is not 2 or 
            len(len) is not 2 or 
            len(sqn) is not 2 or 
            len(rnd) is not 6 or 
            len(rsv) is not 2 or 
            rsv != bytes(2)):
            raise ValueError('Incompatible values set')
        self.ver = ver
        self.typ = typ
        self.len = len
        self.sqn = sqn
        self.rnd = rnd
        self.rsv = rsv
        self.content = bytes(len)
        self.mac = bytes(12)

    def setContent(self, data: bytes) -> None:
        cipher = AES.new(bytes(0), AES.MODE_GCM, mac_len=12)
        epd, mac = cipher.encrypt_and_digest(data)
        self.content = epd
        self.mac = mac
        length = len(self.content) + 16 + len(self.mac) #Magic 16 should represent the len(header)
        self.len = length.to_bytes(2, 'big', signed=False)


class MTPv1Message(MTPMessage):
    def __init__(self, typ: bytes, len: bytes, sqn: bytes) -> None:
        rnd = get_random_bytes(6)
        super().__init__(bytes.fromhex('0100'), typ, len, sqn, rnd, bytes.fromhex('0000'))


class LoginRequest(MTPv1Message):
    def __init__(self, sqn = bytes(2)) -> None:
        super().__init__(typ = bytes.fromhex('0000'), len = bytes(2), sqn = sqn)


class LoginResponse(MTPv1Message):
    def __init__(self, typ: bytes, len: bytes, sqn: bytes) -> None:
        super().__init__(typ, len, sqn)

    # It then encrypts the payload of the login response and produces an authentication tag on the message header 
    # and the encrypted payload using AES in GCM mode with tk as the key and sqn+rnd as the nonce. 
    # In this way the epd and mac fields are produced, and the login response is sent to the client.
    def createFromContent(content: bytes):
        pass
