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
        self.header_ver = b'\x01\x00'

    def check_version(self, header_version):
        print("Checking header version")
        if header_version != self.header_ver:
            print(f'Header version is not matching:\n'
                  f'Expected: {self.header_ver}\n'
                  f'Message header version: {header_version}')
            return False
        return True

    def check_length(self, header_length):
        print("Checking response length")
        if len(self.message) != int.from_bytes(header_length, byteorder='big'):
            print(f"Length did not match:\n"
                  f"Message length: {len(self.message)}\n"
                  f"Lenght in header: {int.from_bytes(header_length, byteorder='big')}")
            return False
        return True

    def check_sqn(self, res_sqn, sqn):
        print("Checking sequence number")
        if res_sqn <= sqn:
            print(f"Sequence number was lower or equal:\n"
                  f"Expected higher than: {sqn}\n"
                  f"Got: {res_sqn}")
            return False
        return True

    def check_type(self, res_type, expected_type):
        print("Checking response type")
        if expected_type != res_type:
            print("Type mismatch")
            return False
        return True

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

        # check version, length, seq number and message type
        res_sqn = int.from_bytes(header_sqn, byteorder='big')
        sqn = int.from_bytes(self.sqn, byteorder='big')

        res_type = int.from_bytes(header_type, byteorder='big')
        expected_type = int.from_bytes(self.expected_type, byteorder='big')

        decrypted_payload = None
        if self.check_version(header_version) and \
                self.check_sqn(res_sqn, sqn) and \
                self.check_type(res_type, expected_type) and \
                self.check_length(header_length):
            # check mac
            print("Checking response mac")
            nonce = header_sqn + header_rnd
            AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
            AE.update(header + nonce + self.message)
            try:
                print(mac)
                decrypted_payload = AE.decrypt_and_verify(encrypted_payload, mac)
            except Exception as e:
                print(f"Error: {e}")
                return None, None

        return decrypted_payload


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

    def create_request(self, key):
        print("Generating a request...")
        enc_pyl, mac = self.encrypt_message(key)
        full_message = self.header + enc_pyl + mac
        return full_message

    def calc_message_len(self):
        print(f"Calculating message length")
        # ver = 2, typ = 2, len = 2, sqn = 2, rnd = 6, rsv = 2
        msg_length = 0
        if self.typ == b'\x00\x00':
            msg_length = self.login_message_length()
        else:
            header_length = 16
            payload_length = len(self.message)
            mac_length = 12
            msg_length_int = header_length + payload_length + mac_length
            msg_length = msg_length_int.to_bytes(2, 'big')
        print(f"Message length: {msg_length}")
        return msg_length

    def mtp_login_request(self, pubkey):
        print(f"MTP Login request function")
        tk, enc_pyl, mac = self.encrypt_first_message()
        print("OK")
        #self.len = self.login_message_length()
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
        print(f"\nmac langth: {len(mac)}\n"
              f"header length: {len(self.header)}\n"
              f"pyl length: {len(enc_pyl)}\n"
              f"ectk len: {len(enc_tk)}\n")
        print(f"Full message sent back: {full_message}")
        return full_message, tk

    def generate_mac(self, key, nonce, encrypted_payload):
        print(f"Generating the mac...")
        self.header = self.create_header()
        #MAC = HMAC.new(key)
        # ? JO A SORREND???
        #MAC.update(self.header + nonce + encrypted_payload)
        #mac = MAC.digest()
        cipehr = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipehr.update(self.header)
        cipehr.update(encrypted_payload)
        mac = cipehr.digest()
        print(f"Mac generated: {mac}")
        return mac

    def login_message_length(self):
        print(f"Calculating login message length")
        # ver = 2, typ = 2, len = 2, sqn = 2, rnd = 6, rsv = 2
        header_length = 16
        payload_length = len(self.message)
        print(f"Payload length: {payload_length}")
        mac_length = 12
        msg_length = header_length + payload_length + mac_length + 256  # encrypted temporary key
        print(f"Login message length: {msg_length}\n"
              f"Login message length in bytes: {msg_length.to_bytes(2, 'big')}")
        return msg_length.to_bytes(2, 'big')

    def encrypt_message(self, key):
        print("Encrypting the message...")
        nonce = self.sqn + self.fresh_random
        ENC = AES.new(key, AES.MODE_GCM, nonce)
        encrypted_payload = None
        try:
            encrypted_payload = ENC.encrypt(self.message.encode('utf-8'))
            print("Payload encrypted")
        except Exception as e:
            print(e)
        print(f"Encrypted: {encrypted_payload}")
        return encrypted_payload, self.generate_mac(key, nonce, encrypted_payload)

    def encrypt_first_message(self):
        print(f"Encrypting the login message...")
        tk = Random.get_random_bytes(32)
        nonce = self.sqn + self.fresh_random
        ENC = AES.new(tk, AES.MODE_GCM, nonce)
        encrypted_payload = None
        try:
            encrypted_payload = ENC.encrypt(self.message.encode('utf-8'))
            print("Payload encrypted")
        except Exception as e:
            print(e)
        print(f"Encryption: \n"
              f"nonce {nonce}\n"
              f"tk: {tk}\n"
              f"encrypted payload: {encrypted_payload}")
        return tk, encrypted_payload, self.generate_mac(tk, nonce, encrypted_payload)


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
        self.message = login_req_message

    def parse_message(self):
        self.payload = MTPResponseMessage(self.message, self.sqn, self.type, self.key).mtp_response()
        if self.payload is None:
            return None, None
        paylod_array = self.payload.split('\n')
        if paylod_array[0] != self.original_hash:
            return None, None
        return paylod_array, (int.from_bytes(self.sqn, 'big') + 1).to_bytes(2, byteorder='big')


class CommandRequestMessage:
    def __init__(self, message, sqn, key):
        self.message = message
        self.key = key
        self.typ = b'\x01\x00'
        self.sqn = sqn

    def command_request(self):
        return self.handle_message_to_mtp(), self.create_request_sha256()

    def handle_message_to_mtp(self):
        return MTPRequestMessage(self.message, self.typ, self.sqn).create_request(self.key)

    def create_request_sha256(self):
        print("Creating the SHA256 hash of the message...")
        h = SHA256.new()
        h.update(str.encode(self.message))
        hashed = h.digest()
        print(f"Message hash: {h.hexdigest()}")
        return hashed


class CommandResponseMessage:
    def __init__(self):
        pass

    def command_response(self):
        # returns the decrypted message
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
