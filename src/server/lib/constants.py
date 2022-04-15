
class MTPConstants:
    LoginRequestType         = bytes.fromhex("00 00")
    LoginResponseType        = bytes.fromhex("00 10")
    CommandRequestType       = bytes.fromhex("01 00")
    CommandResponseType      = bytes.fromhex("01 10")
    UploadRequest0Type       = bytes.fromhex("02 00")
    UploadRequest1Type       = bytes.fromhex("02 01")
    UploadResponseType       = bytes.fromhex("02 10")
    DownloadRequestType      = bytes.fromhex("03 00")
    Download0ResponseType    = bytes.fromhex("03 01")
    Download1ResponseType    = bytes.fromhex("03 10")
