import sys
import time
from xml.dom import ValidationErr
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, PKCS1_OAEP


class MessageBase:
    def __init__(self, ver: bytes, typ: bytes, len: bytes, sqn: bytes, rnd: bytes, rsv: bytes) -> None:
        if (len(ver) != 2): raise ValueError("version should be exactly 2 bytes")
        if (len(typ) != 2): raise ValueError("")
        if (len(sqn) != 2): raise ValueError("")
        if (len(len) != 2): raise ValueError("")
        if (len(rnd) != 6): raise ValueError('')
        if (len(rsv) != 2): raise ValueError('')
        self.ver = ver
        self.typ = typ
        self.sqn = sqn
        self.rnd = rnd
        self.rsv = rsv

    def setContent(self, content: bytes) -> None:
        self.content = content


class MTPResponseMessage:
    def __init__(self, message, req_sqn, res_type, key):
        self.expected_type = res_type
        self.message = message
        self.sqn = req_sqn
        self.key = key

    def mtp_response(self):
        header = self.message[0:16]  # header is 16 bytes long
        mac = self.message[-12:]  # last 12 bytes is the authtag
        encrypted_payload = self.message[16:-12]  # encrypted payload is between header and mac
        header_version = header[0:2]  # version is encoded on 2 bytes
        header_type = header[2:4]  # type is encoded on 2 byte
        header_length = header[4:6]  # msg length is encoded on 2 bytes
        header_sqn = header[6:8]  # msg sqn is encoded on 4 bytes
        header_rnd = header[8:14]  # random is encoded on 7 bytes
        header_rsv = header[14:16]  # random is encoded on 7 bytes

        # check length
        if len(self.message) != int.from_bytes(header_length, byteorder='big'):
            return 0, 0

        # check sequence number
        res_sqn = int.from_bytes(header_sqn, byteorder='big')
        if res_sqn <= self.sqn:
            return 0, 0

        # check message type
        res_type = int.from_bytes(header_type, byteorder='big')
        expected_type = int.from_bytes(self.expected_type, byteorder='big')
        if expected_type != res_type:
            return 0, 0

        # check mac
        nonce = header_sqn + header_rnd
        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        AE.update(header + nonce + self.message)
        try:
            decrypted_payload = AE.decrypt_and_verify(encrypted_payload, mac)
        except Exception as e:
            return 0, 0

        return header, decrypted_payload


class MTPRequestMessage:
    def __init__(self, message, typ, sqn):
        self.header = None
        self.message = message
        self.ver = b'\x01\x00'
        self.typ = typ
        self.sqn = sqn
        self.len = self.calc_message_len()
        self.fresh_random = Random.get_random_bytes(6)
        self.rsv = b'\x00\x00'

    def create_header(self):
        return self.ver + self.typ + self.len + self.sqn + self.fresh_random + self.rsv

    def create_request(self):
        pass

    def calc_message_len(self):
        # ver = 2, typ = 2, len = 2, sqn = 2, rnd = 6, rsv = 2
        header_length = 16
        payload_length = len(self.message)
        # padding_length = AES.block_size - payload_length % AES.block_size
        mac_length = 12
        msg_length = header_length + payload_length + mac_length
        return msg_length.to_bytes(2, 'big')

    def mtp_login_request(self, pubkey):
        tk, enc_pyl, mac = self.encrypt_first_message()
        self.len = self.login_message_length()
        # Encrypt the temp key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(pubkey)
        enc_tk = cipher_rsa.encrypt(tk)

        full_message = self.header + enc_pyl + mac + enc_tk
        return full_message, tk

    def generate_mac(self, key, nonce, encrypted_payload):
        self.header = self.create_header()
        MAC = HMAC.new(key)
        # ? JO A SORREND???
        MAC.update(self.header + nonce + encrypted_payload)
        return MAC.digest()

    def login_message_length(self):
        # ver = 2, typ = 2, len = 2, sqn = 2, rnd = 6, rsv = 2
        header_length = 16
        payload_length = len(self.message)
        mac_length = 12
        msg_length = header_length + payload_length + mac_length + 256  # encrypted temporary key
        return msg_length.to_bytes(2, 'big')

    def encrypt_first_message(self):
        tk = Random.get_random_bytes(32)
        nonce = self.sqn + self.fresh_random
        ENC = AES.new(tk, AES.MODE_GCM, nonce)
        encrypted_payload = ENC.encrypt(self.message)
        return tk, encrypted_payload, self.generate_mac(tk, nonce, encrypted_payload)

    # TODO The client and the server also send random values
    #  client_random and server_random, respectively,
    #  in the payload of the login request and login response messages,
    #  and they use these random numbers to create the final transfer key
    #  that they will use in the rest of the session.


class LoginRequestMessage:
    def __init__(self, key_path, credentials, sqn):
        self.client_random = None
        self.request_sha256 = None
        self.typ = b'\x00\x00'
        self.sqn = sqn
        self.key = None
        self.key_path = key_path
        self.credentials = credentials
        self.mtp_message = self.create_mtp_message()
        self.load_publickey()

    def login_request(self):
        full_message, tk = self.handle_message_to_mtp()
        return full_message, self.create_request_sha256(), self.client_random, tk

    def create_request_sha256(self):
        h = SHA256.new()
        h.update(str.encode(self.mtp_message))
        return h.digest()

    def handle_message_to_mtp(self):
        return MTPRequestMessage(self.mtp_message, self.typ, self.sqn).mtp_login_request(self.key)

    def create_mtp_message(self):
        self.client_random = Random.get_random_bytes(16).hex()
        message = str(time.time_ns()) + "\n" + \
                  self.credentials[0] + "\n" + \
                  self.credentials[1] + "\n" + \
                  self.client_random
        return message

    def load_publickey(self):
        with open(self.key_path, 'rb') as f:
            self.key = f.read()
        try:
            return RSA.import_key(self.key)
        except ValueError:
            print('Error: Cannot import public key from file ' + self.key_path)
            sys.exit(1)


class LoginResponseMessage:
    def __init__(self, login_req_message, original_sqn, key, original_hash):
        self.original_hash = original_hash
        self.key = key
        self.type = b'\x00\x10'
        self.sqn = original_sqn
        self.payload = None
        self.header = None
        self.message = login_req_message

    def parse_message(self):
        self.header, self.payload = MTPResponseMessage(self.message, self.sqn, self.type, self.key).mtp_response()
        if self.header == 0:
            return 0, 0
        paylod_array = self.payload.split('\n')
        if paylod_array[0] != self.original_hash:
            return 0, 0
        return paylod_array[1], self.sqn+1


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
