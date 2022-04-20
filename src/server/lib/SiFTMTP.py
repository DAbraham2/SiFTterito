from typing_extensions import Self
from Crypto.Random import get_random_bytes
from lib.constants import MTPConstants
from lib.cryptoStuff import decryptMessage, decryptLoginRequestETK, encryptMessage


class MTPMessage(object):
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

    def getHeader(self) -> bytes:
        return self.ver + self.typ + self.len + self.sqn + self.rnd + self.rsv

    def setContent(self, data: bytes, *, tk:bytes = bytes(16)) -> None:
        self.len = 16 + len(data) + 12
        self.content, self.mac = encryptMessage(data, self.getHeader(), tk)
        

    def getMessageAsBytes(self) -> bytes:
        return self.getHeader() + self.content + self.mac

    @classmethod
    def createFromContent(cls, data: bytes):
        pass


class MTPv1Message(MTPMessage):

    def __init__(self, *, 
        ver: bytes = bytes.fromhex('0100'), 
        typ: bytes = bytes.fromhex('ffff'), 
        _len: bytes = bytes(2), 
        sqn: bytes = bytes(2), 
        rnd: bytes = get_random_bytes(6), 
        rsv: bytes = bytes(2)) -> None:
        if ver != bytes.fromhex('01 00'):
            raise ValueError()

        super().__init__(ver, typ, _len, sqn, rnd, rsv)


class LoginRequest(MTPv1Message):
    """
    Login Request class
    """
    def __init__(self,  timestamp: int, username: str,
                        password: str, client_secret: bytes, tk:bytes, *, 
                        ver: bytes = bytes.fromhex('0100'), typ: bytes = bytes.fromhex('0000'), 
                        _len: bytes = bytes(2), sqn: bytes = bytes(2), 
                        rnd: bytes = get_random_bytes(6), rsv: bytes = bytes(2)) -> None:
        if typ != bytes.fromhex('00 00'):
            raise ValueError('Wrong type')
        super().__init__(   ver=ver,
                            typ=typ,
                            _len=_len,
                            sqn=sqn,
                            rnd=rnd,
                            rsv=rsv)
        self.timestamp = timestamp
        self.username = username
        self.password = password
        self.client_secret = client_secret
        self.temporary_key = tk

    @classmethod
    def createFromContent(cls, data: bytes):
        """Creates a LoginRequest object from a recieved message

        :param data: The recieved message
        :type data: bytes
        :returns: a new LoginRequest object
        :rtype: LoginRequest
        """

        ver = data[0: 2]
        typ = data[2: 4]
        _len = data[4: 6]
        sqn = data[6: 8]
        rnd = data[8:14]
        rsv = data[14:16]

        body = data[16:-256]
        etk = data[-256:]
        
        tk = decryptLoginRequestETK(etk)
        content = decryptMessage(body, data[:16], tk)
        content_str = content.decode('utf-8')
        content_arr = content_str.splitlines()

        if len(content_arr) != 4:
            raise ValueError('')

        timestamp = int(content_arr[0])
        username = content_arr[1]
        password = content_arr[2]
        client_random = bytes.fromhex(content_arr[3])

        return cls(timestamp, username, password, client_random, tk, ver=ver, typ=typ, _len=_len, sqn=sqn, rnd=rnd,rsv=rsv)


class LoginResponse(MTPv1Message):
    def __init__(self, payload: bytes, sqn: bytes, *, tk: bytes = bytes(32)) -> None:
        _len = (16+len(payload)+12).to_bytes(2, 'big')
        super().__init__(typ=bytes.fromhex('0010'), _len=_len, sqn=sqn)
        self.setContent(payload, tk=tk)


    # It then encrypts the payload of the login response and produces an authentication tag on the message header
    # and the encrypted payload using AES in GCM mode with tk as the key and sqn+rnd as the nonce.
    # In this way the epd and mac fields are produced, and the login response is sent to the client.
    @classmethod
    def createFromContent(cls, data: bytes):
        raise ValueError('Should not be called')


class MessageFactory:
    def create(header: bytes, body: bytes) -> MTPv1Message:
        typ = header[2:4]
        match typ:
            case MTPConstants.LoginRequestType:
                return LoginRequest.createFromContent(header+body)
            case MTPConstants.CommandRequestType:
                pass
            case MTPConstants.UploadRequest0Type:
                pass
            case MTPConstants.UploadRequest1Type:
                pass
            case MTPConstants.DownloadRequestType:
                pass
