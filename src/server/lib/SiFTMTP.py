from Crypto.Random import get_random_bytes

from lib.constants import MTPConstants
from lib.cryptoStuff import (decryptLoginRequestETK, decryptMessage,
                             encryptMessage)

import logging

logger = logging.getLogger(__name__)

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

    def __init__(self, ver: bytes, typ: bytes, _len: bytes, sqn: bytes, rnd: bytes, rsv: bytes, *, content: bytes = bytes(0)) -> None:
        if (not len(ver) is 2 or
            not len(typ) is 2 or
            not len(_len) is 2 or
            not len(sqn) is 2 or
            not len(rnd) is 6 or
            not len(rsv) is 2 or
                rsv != bytes(2)):
            raise ValueError('Incompatible values set')
        self.ver = ver
        self.typ = typ
        self.len = _len
        self.sqn = sqn
        self.rnd = rnd
        self.rsv = rsv
        self.content = content
        self.mac = bytes(12)

    def getHeader(self) -> bytes:
        return self.ver + self.typ + self.len + self.sqn + self.rnd + self.rsv

    def setContent(self, data: bytes, *, tk: bytes = bytes(16)) -> None:
        self.len = 16 + len(data) + 12
        self.content, self.mac = encryptMessage(data, self.getHeader(), tk)

    def getMessageAsBytes(self) -> bytes:
        return self.getHeader() + self.content + self.mac

    @classmethod
    def createFromContent(cls, data: bytes, *, transfer_key: bytes):
        header = data[:16]
        epd = data[16:]
        payload = decryptMessage(epd, header, transfer_key)
        return cls(header[:2], header[2:4],
                   header[4:6], header[6:8],
                   header[8:14], header[14:16],
                   content=payload)


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
                 password: str, client_secret: bytes, tk: bytes, *,
                 ver: bytes = bytes.fromhex('0100'), typ: bytes = bytes.fromhex('0000'),
                 _len: bytes = bytes(2), sqn: bytes = bytes(2),
                 rnd: bytes = get_random_bytes(6), rsv: bytes = bytes(2)) -> None:
        if typ != bytes.fromhex('00 00'):
            raise ValueError('Wrong type')
        super().__init__(ver=ver,
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
    def createFromContent(cls, data: bytes, *, transfer_key: bytes):
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
        logger.info('LoginRequest.createFromContent content: ' + content_str)
        content_arr = content_str.splitlines()

        if len(content_arr) != 4:
            raise ValueError('Payload is not right\n{}'.format(content_str))

        timestamp = int(content_arr[0])
        username = content_arr[1]
        password = content_arr[2]
        client_random = bytes.fromhex(content_arr[3])

        return cls(timestamp, username, password, client_random, tk, ver=ver, typ=typ, _len=_len, sqn=sqn, rnd=rnd, rsv=rsv)


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


class CommandRequest(MTPv1Message):
    def __init__(self, *, ver: bytes = bytes.fromhex('0100'),
                 typ: bytes = bytes.fromhex('ffff'),
                 _len: bytes = bytes(2),
                 sqn: bytes = bytes(2),
                 rnd: bytes = get_random_bytes(6),
                 rsv: bytes = bytes(2),
                 content: bytes = bytes(0)) -> None:
        super().__init__(ver=ver, typ=typ, len=_len, sqn=sqn, rnd=rnd, rsv=rsv)
        self.content = content


class CommandResponse(MTPv1Message):
    def __init__(self, *, ver: bytes = bytes.fromhex('0100'), typ: bytes = bytes.fromhex('ffff'), _len: bytes = bytes(2), sqn: bytes = bytes(2), rnd: bytes = get_random_bytes(6), rsv: bytes = bytes(2)) -> None:
        super().__init__(ver=ver, typ=typ, len=_len, sqn=sqn, rnd=rnd, rsv=rsv)

    @classmethod
    def createFromContent(cls, data: bytes, *, transfer_key: bytes):
        sqn = data[6:8]
        c = cls(typ=MTPConstants.CommandResponseType, sqn=sqn)
        c.setContent(data[16:], tk=transfer_key)
        return c


class DownloadRequest(MTPv1Message):
    pass


class DownloadResponse0(MTPv1Message):
    @classmethod
    def createFromContent(cls, data: bytes, *, transfer_key: bytes):
        sqn = data[6:8]
        c = cls(typ=MTPConstants.Download0ResponseType, sqn=sqn)
        c.setContent(data[16:], tk=transfer_key)
        return c


class DownloadResponse1(MTPv1Message):
    @classmethod
    def createFromContent(cls, data: bytes, *, transfer_key: bytes):
        sqn = data[6:8]
        c = cls(typ=MTPConstants.Download1ResponseType, sqn=sqn)
        c.setContent(data[16:], tk=transfer_key)
        return c


class MessageFactory:
    def create(header: bytes, body: bytes, *, transfer_key: bytes = None) -> MTPv1Message:
        typ = header[2:4]
        data = header+body
        match typ:
            case MTPConstants.LoginRequestType:
                return LoginRequest.createFromContent(data, transfer_key=transfer_key)
            case MTPConstants.CommandRequestType:
                return CommandRequest.createFromContent(data, transfer_key=transfer_key)
            case MTPConstants.CommandResponseType:
                return CommandResponse.createFromContent(data, transfer_key=transfer_key)
            case MTPConstants.UploadRequest0Type:
                pass
            case MTPConstants.UploadRequest1Type:
                pass
            case MTPConstants.DownloadRequestType:
                return DownloadRequest.createFromContent(data, transfer_key=transfer_key)
            case MTPConstants.Download0ResponseType:
                return DownloadResponse0.createFromContent(data, transfer_key=transfer_key)
            case MTPConstants.Download1ResponseType:
                return DownloadResponse1.createFromContent(data, transfer_key=transfer_key)
            case _:
                raise ValueError('typ undefined')
