from xml.dom import ValidationErr


class MessageBase:
    def __init__(self, ver: bytes, typ: bytes, len: bytes, sqn: bytes, rnd: bytes, rsv: bytes) -> None:
        if (len(ver) != 2): raise ValueError("version should be exactly 2 bytes")
        if(len(typ) != 2): raise ValueError("")
        if(len(sqn) != 2): raise ValueError("")
        if(len(len) != 2): raise ValueError("")
        if(len(rnd) != 6): raise ValueError('')
        if(len(rsv) != 2): raise ValueError('')
        self.ver = ver
        self.typ = typ
        self.sqn = sqn
        self.rnd = rnd
        self.rsv = rsv

    def setContent(self, content: bytes) -> None:
        self.content = content


class LoginRequestMessage(MessageBase):
    pass

class LoginResponseMessage(MessageBase):
    pass

class CommandRequestMessage(MessageBase):
    pass

class CommandResponseMessage(MessageBase):
    pass

class UploadRequestMessage(MessageBase):
    pass

class UploadRequest1Message(MessageBase):
    pass

class UploadResponseMessage(MessageBase):
    pass

class DnloadRequestMessage(MessageBase):
    pass

class DnloadResponse0Message(MessageBase):
    pass

class DnloadResponse1Message(MessageBase):
    pass

