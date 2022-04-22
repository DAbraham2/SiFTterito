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
        print("Checking response length")
        if len(self.message) != int.from_bytes(header_length, byteorder='big'):
            print("Length did not match")
            return 0, 0

        # check sequence number
        print("Checking sequence number")
        res_sqn = int.from_bytes(header_sqn, byteorder='big')
        if res_sqn <= self.sqn:
            print("Sequence number was lower or equal")
            return 0, 0

        # check message type
        print("Checking response type")
        res_type = int.from_bytes(header_type, byteorder='big')
        expected_type = int.from_bytes(self.expected_type, byteorder='big')
        if expected_type != res_type:
            print("Type mismatch")
            return 0, 0

        # check mac
        print("Checking response mac")
        nonce = header_sqn + header_rnd
        AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        AE.update(header + nonce + self.message)
        try:
            decrypted_payload = AE.decrypt_and_verify(encrypted_payload, mac)
        except Exception as e:
            print(f"Error: {e}")
            return 0, 0

        return header, decrypted_payload


class MTPRequestMessage:
    def __init__(self, message, typ, sqn):
        print(f"MTP Request Initialization...")
        self.header = None
        self.message = message
        self.ver = b'\x01\x00'
        self.typ = typ
        self.sqn = sqn
        self.len = self.calc_message_len()
        self.fresh_random = Random.get_random_bytes(6)
        self.rsv = b'\x00\x00'

    def create_header(self):
        print(f"Creating the header...")
        return self.ver + self.typ + self.len + self.sqn + self.fresh_random + self.rsv

    def create_request(self):
        pass

    def calc_message_len(self):
        print(f"Calculating message length")
        # ver = 2, typ = 2, len = 2, sqn = 2, rnd = 6, rsv = 2
        header_length = 16
        payload_length = len(self.message)
        # padding_length = AES.block_size - payload_length % AES.block_size
        mac_length = 12
        msg_length = header_length + payload_length + mac_length
        print(f"Message length: {msg_length}\n"
              f"Message length in bytes: {msg_length.to_bytes(2, 'big')}")
        return msg_length.to_bytes(2, 'big')

    def mtp_login_request(self, pubkey):
        print(f"MTP Login request function")
        tk, enc_pyl, mac = self.encrypt_first_message()
        print("OK")
        self.len = self.login_message_length()
        # Encrypt the temp key with the public RSA key
        print(f"Encrypt TK using public key...")
        enc_tk = None
        try:
            cipher_rsa = PKCS1_OAEP.new(pubkey)
            enc_tk = cipher_rsa.encrypt(tk)
            print(f"Encrypted tk: {enc_tk}")
        except Exception as e:
            print(e)
        full_message = self.header + enc_pyl + mac + enc_tk
        print(f"Full message sent back: {full_message}")
        return full_message, tk

    def generate_mac(self, key, nonce, encrypted_payload):
        print(f"Generating the mac...")
        self.header = self.create_header()
        MAC = HMAC.new(key)
        # ? JO A SORREND???
        MAC.update(self.header + nonce + encrypted_payload)
        mac = MAC.digest()
        print(f"Mac generated: {mac}")
        return mac

    def login_message_length(self):
        print(f"Calculating login message length")
        # ver = 2, typ = 2, len = 2, sqn = 2, rnd = 6, rsv = 2
        header_length = 16
        payload_length = len(self.message)
        mac_length = 12
        msg_length = header_length + payload_length + mac_length + 256  # encrypted temporary key
        print(f"Login message length: {msg_length}\n"
              f"Login message length in bytes: {msg_length.to_bytes(2, 'big')}")
        return msg_length.to_bytes(2, 'big')

    def encrypt_first_message(self):
        print(f"Encrypting the login message...")
        tk = Random.get_random_bytes(32)
        nonce = self.sqn + self.fresh_random
        ENC = AES.new(tk, AES.MODE_GCM, nonce)
        encrypted_payload = None
        try:
            #TODO hibakodot megnezni
            encrypted_payload = ENC.encrypt(self.message.encode('utf-8'))
            print("Payload encrypted")
        except Exception as e:
            print(e)
        print(f"Encryption: \n"
              f"nonce {nonce}\n"
              f"tk: {tk}\n"
              f"encrypted payload: {encrypted_payload}")
        return tk, encrypted_payload, self.generate_mac(tk, nonce, encrypted_payload)

    # TODO The client and the server also send random values
    #  client_random and server_random, respectively,
    #  in the payload of the login request and login response messages,
    #  and they use these random numbers to create the final transfer key
    #  that they will use in the rest of the session.


class LoginRequestMessage:
    def __init__(self, key_path, credentials, sqn):
        print("Login Request Initialization...")
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
        print("Login request function")
        full_message, tk = self.handle_message_to_mtp()
        print(f"Message from MTP: {full_message}")
        print(f"TK from MTP: {tk}")
        return full_message, self.create_request_sha256(), self.client_random, tk

    def create_request_sha256(self):
        print("Creating the SHA256 hash of the message...")
        h = SHA256.new()
        h.update(str.encode(self.mtp_message))
        hashed = h.digest()
        print(f"Message hash: {h.hexdigest()}")
        return hashed

    def handle_message_to_mtp(self):
        print("Handling message to MTP Protocol...")
        return MTPRequestMessage(self.mtp_message, self.typ, self.sqn).mtp_login_request(self.key)

    def create_mtp_message(self):
        print(f"Creating MTP Login Message...")
        self.client_random = Random.get_random_bytes(16).hex()
        message = str(time.time_ns()) + "\n" + \
                  self.credentials[0] + "\n" + \
                  self.credentials[1] + "\n" + \
                  self.client_random
        print(f"Created message: {message}")
        return message

    def load_publickey(self):
        print("Loading the public key...")
        with open(self.key_path, 'rb') as f:
            key = f.read()
            try:
                self.key = RSA.import_key(key)
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
