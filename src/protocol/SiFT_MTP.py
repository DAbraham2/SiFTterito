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


class MTPRequestMessage:
    def __init__(self, message, typ, sqn):
        self.message = message
        self.ver = b'\x01\x00'
        self.typ = typ
        self.sqn = sqn
        self.len = self.calc_message_len(message)
        self.fresh_random = Random.get_random_bytes(6)
        self.rsv = b'\x00\x00'


    def create_header(self):
        return self.ver + self.typ + self.len + self.sqn + self.fresh_random + self.rsv

    def create_request(self):
        pass

    def calc_message_len(self, message):
        # ver = 2, typ = 2, len = 2, sqn = 2, rnd = 6, rsv = 2
        header_length = 16
        payload_length = len(message)
        #padding_length = AES.block_size - payload_length % AES.block_size
        mac_length = 12
        msg_length = header_length + payload_length  + mac_length
        return msg_length.to_bytes(2, 'big')

    def mtp_login_request(self, pubkey):
        tk, enc_pyl, mac = self.encrypt_first_message()

        # Encrypt the temp key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(pubkey)
        enc_tk = cipher_rsa.encrypt(tk)

    def generate_mac(self, tk, nonce, encrypted_payload):
        header = self.create_header()
        MAC = HMAC.new(tk)
        MAC.update(header + nonce + encrypted_payload)
        mac = MAC.digest()

    def login_message_length(self, message):
        # ver = 2, typ = 2, len = 2, sqn = 2, rnd = 6, rsv = 2
        header_length = 16
        payload_length = len(message)
        #padding_length = AES.block_size - payload_length % AES.block_size
        mac_length = 12
        msg_length = header_length + payload_length + mac_length + 256 #encrypted temporary key
        return msg_length.to_bytes(2, 'big')

    def encrypt_first_message(self):
        tk = Random.get_random_bytes(32)
        nonce = self.sqn + self.fresh_random
        ENC = AES.new(tk, AES.MODE_GCM, nonce)
        encrypted_payload = ENC.encrypt(self.message)
        return tk, encrypted_payload, self.generate_mac(tk, nonce, encrypted_payload)

        #TODO The client and the server also send random values client_random and server_random, respectively, in the payload of the login request and login response messages, and they use these random numbers to create the final transfer key that they will use in the rest of the session.
        #TODO socket/req-res with sockets

class LoginRequestMessage:
    def __init__(self, key_path, request_message, credentials, mtp_rotocol):
        self.mtp_rotocol = mtp_rotocol
        self.typ = b'\x00\x00'
        self.sqn = b'\x00\x01'
        self.hashed_login_request = None
        self.key = None
        self.key_path = key_path
        self.message = request_message
        self.credentials = credentials
        self.type = b'\x00\x00'
        self.load_publickey()

        self.mtp_message = self.create_mtp_message()
        self.response = self.handle_message_to_mtp()
        self.request_sha256 = self.create_request_sha256()

    def create_request_sha256(self):
        h = SHA256.new()
        h.update(str.encode(self.mtp_message))
        self.hashed_login_request = h.digest()

    def handle_message_to_mtp(self):
        return self.mtp_rotocol(self.mtp_message, self.typ, self.sqn).mtp_login_request(self.key)

    def create_mtp_message(self):
        message = str(time.time_ns()) + "\n" + \
                  self.credentials[0] + "\n" + \
                  self.credentials[1] + "\n" + \
                  Random.get_random_bytes(16).hex() + "\n"
        return message

    def load_publickey(self):
        with open(self.key_path, 'rb') as f:
            self.key = f.read()
        try:
            return RSA.import_key(self.key)
        except ValueError:
            print('Error: Cannot import public key from file ' + self.key_path)
            sys.exit(1)


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
