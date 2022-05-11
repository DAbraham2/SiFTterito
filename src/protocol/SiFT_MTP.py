import sys
import time
from xml.dom import ValidationErr
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, PKCS1_OAEP
import logging


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
        self.logger = logging.getLogger(__name__)
        self.logger.info("mtp response init")
        self.expected_type = res_type
        self.message = message
        self.sqn = req_sqn
        self.key = key
        self.header_ver = b'\x01\x00'

    def check_version(self, header_version):
        print("Checking header version")
        self.logger.info("check_version")
        if header_version != self.header_ver:
            self.logger.debug(f'Header version is not matching:\n'
                              f'Expected: {self.header_ver}\n'
                              f'Message header version: {header_version}')
            return False
        return True

    def check_length(self, header_length):
        self.logger.info("length check")
        print("Checking response length")
        if len(self.message) != int.from_bytes(header_length, byteorder='big'):
            print(f"Length did not match:\n"
                  f"Message length: {len(self.message)}\n"
                  f"Lenght in header: {int.from_bytes(header_length, byteorder='big')}")
            return False
        return True

    def check_sqn(self, res_sqn, sqn):
        self.logger.info("sqn check")
        print("Checking sequence number")
        '''
        if res_sqn <= sqn:
            self.logger.debug(f"Sequence number was lower or equal:\n"
                              f"Expected higher than: {sqn}\n"
                              f"Got: {res_sqn}")
            return False
        '''
        return True

    def check_type(self, res_type, expected_type):
        self.logger.info("type check")
        print("Checking response type")
        if expected_type != res_type:
            self.logger.debug(f"Expected type: {expected_type}\nResponse type: {res_type}")
            return False
        return True

    def mtp_response(self):
        self.logger.info("mtp response")
        header = self.message[0:16]  # header is 16 bytes long
        self.logger.debug(f"HEADER: {header}")
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
            self.logger.info("Checking response mac")
            nonce = header_sqn + header_rnd
            AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
            AE.update(header)
            try:
                self.logger.debug(mac)
                self.logger.info("decrypt and mac verify")
                decrypted_payload = AE.decrypt_and_verify(encrypted_payload, mac)
                self.logger.debug(decrypted_payload)
            except Exception as e:
                print(f"Error: {e}")
                self.logger.error(f"Error: {e}")
                return None, None

        return decrypted_payload

    def decrypt_download(self):
        self.logger.info("mtp download response")
        header = self.message[0:16]  # header is 16 bytes long
        self.logger.debug(f"HEADER: {header}")
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
        expected_type0 = int.from_bytes(b'\x03\x10', byteorder='big')
        expected_type1 = int.from_bytes(b'\x03\x11', byteorder='big')

        decrypted_payload = None
        if self.check_version(header_version) and \
                self.check_sqn(res_sqn, sqn) and \
                self.check_length(header_length):
            # check mac
            self.logger.info("Checking response mac")
            nonce = header_sqn + header_rnd
            AE = AES.new(self.key, AES.MODE_GCM, nonce=nonce, mac_len=12)
            AE.update(header)
            try:
                self.logger.debug(mac)
                self.logger.info("decrypt and mac verify")
                decrypted_payload = AE.decrypt_and_verify(encrypted_payload, mac)
                self.logger.debug(decrypted_payload)
            except Exception as e:
                print(f"Error: {e}")
                self.logger.error(f"Error: {e}")
                return None, None
        if self.check_type(res_type, expected_type0):
            self.logger.info("Not last d fragment")
            return decrypted_payload, False
        else:
            if self.check_type(res_type, expected_type1):
                self.logger.info("Lst dfragment")
                return decrypted_payload, True
            else:
                self.logger.info("Not matchin type")
                return None, None


class MTPRequestMessage:
    def __init__(self, message, typ, sqn):
        self.logger = logging.getLogger(__name__)
        self.logger.info("mtp response init")
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
        self.logger.info("create header")
        return self.ver + self.typ + self.len + self.sqn + self.fresh_random + self.rsv

    def create_request(self, key):
        self.logger.info("create request")
        print("Generating a request...")
        self.header = self.create_header()
        enc_pyl, mac = self.encrypt_message(key)
        self.logger.info("encrypted")
        full_message = self.header + enc_pyl + mac
        self.logger.debug(f"Full message {full_message}")
        return full_message

    def calc_message_len(self):
        self.logger.info("Mesage length calculation")
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
        self.logger.debug(f"Message length {msg_length}")
        return msg_length

    def mtp_login_request(self, pubkey):
        self.logger.info("mtp login request")
        print(f"MTP Login request function")
        self.header = self.create_header()
        tk, enc_pyl, mac = self.encrypt_first_message()
        self.logger.info("encrypted")
        # self.len = self.login_message_length()
        # Encrypt the temp key with the public RSA key
        print(f"Encrypt TK using public key...")
        self.logger.info("Encrypting TK")
        enc_tk = None
        try:
            cipher_rsa = PKCS1_OAEP.new(pubkey)
            enc_tk = cipher_rsa.encrypt(tk)
            self.logger.debug(f"Encrypted tk: {enc_tk}")
        except Exception as e:
            print(e)
            self.logger.debug(e)
        full_message = self.header + enc_pyl + mac + enc_tk
        self.logger.debug(f"\nmac length: {len(mac)}\n"
                          f"header length: {len(self.header)}\n"
                          f"pyl length: {len(enc_pyl)}\n"
                          f"ectk len: {len(enc_tk)}\n")
        self.logger.debug(f"Full message sent back: {full_message}")
        return full_message, tk

    '''
    def generate_mac(self, key, nonce, encrypted_payload):
        self.logger.info("mac generation")
        print(f"Generating the mac...")
        self.header = self.create_header()
        #MAC = HMAC.new(key)
        # ? JO A SORREND???
        #MAC.update(self.header + nonce + encrypted_payload)
        #mac = MAC.digest()
        cipehr = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipehr.update(self.header)
        #cipehr.update(encrypted_payload)
        mac = cipehr.digest()
        self.logger.debug(f"Mac generated: {mac}")
        return mac
    '''

    def login_message_length(self):
        self.logger.info("login message length calc")
        print(f"Calculating login message length")
        # ver = 2, typ = 2, len = 2, sqn = 2, rnd = 6, rsv = 2
        header_length = 16
        payload_length = len(self.message)
        self.logger.debug(f"Payload length: {payload_length}")
        mac_length = 12
        msg_length = header_length + payload_length + mac_length + 256  # encrypted temporary key
        self.logger.debug(f"Login message length: {msg_length}\n"
                          f"Login message length in bytes: {msg_length.to_bytes(2, 'big')}")
        return msg_length.to_bytes(2, 'big')

    def encrypt_message(self, key):
        self.logger.info("message encryption")
        print("Encrypting the message...")
        nonce = self.sqn + self.fresh_random
        ENC = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        encrypted_payload = None
        mac = None
        try:
            self.logger.debug(self.message)
            self.logger.debug(self.header)
            ENC.update(self.header)
            encrypted_payload, mac = ENC.encrypt_and_digest(self.message.encode('utf-8'))
            self.logger.info("Payload encrypted and Mac calculated")
        except Exception as e:
            print(e)
        self.logger.debug(f"Encrypted: {encrypted_payload}\nMAC: {mac}"
                          f"nonce {nonce}\n")
        return encrypted_payload, mac

    def encrypt_first_message(self):
        self.logger.info("login req encryption")
        print(f"Encrypting the login message...")
        tk = Random.get_random_bytes(32)
        nonce = self.sqn + self.fresh_random
        ENC = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=12)
        encrypted_payload = None
        mac = None
        self.logger.debug(self.message)
        self.logger.debug(self.header)
        try:
            ENC.update(self.header)
            encrypted_payload, mac = ENC.encrypt_and_digest(self.message.encode('utf-8'))
            self.logger.info("Payload encrypted and Mac calculated")
        except Exception as e:
            print(e)
            self.logger.error(e)
        self.logger.debug(f"Encryption: \n"
                          f"MAC: {mac}"
                          f"nonce {nonce}\n"
                          f"tk: {tk}\n"
                          f"encrypted payload: {encrypted_payload}")
        return tk, encrypted_payload, mac


class LoginRequestMessage:
    def __init__(self, key_path, credentials, sqn):
        self.logger = logging.getLogger(__name__)
        self.logger.info("login request init")
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
        self.logger.info("login request func")
        print("Login request function")
        full_message, tk = self.handle_message_to_mtp()
        self.logger.debug(f"Message from MTP: {full_message}")
        self.logger.debug(f"TK from MTP: {tk}")
        return full_message, self.create_request_sha256(), self.client_random, tk

    def create_request_sha256(self):
        self.logger.info("sha256 generation")
        print("Creating the SHA256 hash of the message...")
        h = SHA256.new()
        h.update(self.mtp_message.encode('utf-8'))
        hashed = h.digest()
        self.logger.debug(f"Message hash: {h.hexdigest()}")
        return hashed

    def handle_message_to_mtp(self):
        self.logger.info("handle to mtp")
        print("Handling message to MTP Protocol...")
        return MTPRequestMessage(self.mtp_message, self.typ, self.sqn).mtp_login_request(self.key)

    def create_mtp_message(self):
        self.logger.info("create mtp message")
        print(f"Creating MTP Login Message...")
        self.client_random = Random.get_random_bytes(16).hex()
        message = str(time.time_ns()) + "\n" + \
                  self.credentials[0] + "\n" + \
                  self.credentials[1] + "\n" + \
                  self.client_random
        self.logger.debug(f"Created message: {message}")
        return message

    def load_publickey(self):
        self.logger.info("loading pubkey")
        print("Loading the public key...")
        with open(self.key_path, 'rb') as f:
            key = f.read()
            try:
                self.key = RSA.import_key(key)
            except ValueError:
                self.logger.error(e)
                print('Error: Cannot import public key from file ' + self.key_path)
                sys.exit(1)


class LoginResponseMessage:
    def __init__(self, login_req_message, original_sqn, key, original_hash):
        self.logger = logging.getLogger(__name__)
        self.logger.info("login response init")
        self.original_hash = original_hash
        self.key = key
        self.type = b'\x00\x10'
        self.sqn = original_sqn
        self.payload = None
        self.message = login_req_message

    def parse_message(self):
        self.logger.info("parsing response message")
        self.payload = MTPResponseMessage(self.message, self.sqn, self.type, self.key).mtp_response()
        self.payload = self.payload.decode('utf-8')
        self.logger.debug(self.payload)
        if self.payload is None:
            return None, None
        payload_array = self.payload.split('\n')
        if bytes.fromhex(payload_array[0]) != self.original_hash:
            self.logger.error(f"Hashes do not match:\n"
                              f"Got: {payload_array[0]}\n"
                              f"expected: {self.original_hash}")
            return None, None
        return payload_array, (int.from_bytes(self.sqn, 'big') + 1).to_bytes(2, byteorder='big')


class CommandRequestMessage:
    def __init__(self, message, sqn, key):
        self.logger = logging.getLogger(__name__)
        self.logger.info("command request init")
        self.message = message
        self.key = key
        self.logger.debug(key)
        self.logger.debug(len(key))
        self.typ = b'\x01\x00'
        self.sqn = sqn

    def command_request(self):
        self.logger.info("command request function")
        return self.handle_message_to_mtp(), self.create_request_sha256()

    def handle_message_to_mtp(self):
        self.logger.info("command request to mtp")
        return MTPRequestMessage(self.message, self.typ, self.sqn).create_request(self.key)

    def create_request_sha256(self):
        self.logger.info("command request sha256")
        print("Creating the SHA256 hash of the message...")
        h = SHA256.new()
        h.update(str.encode(self.message))
        hashed = h.digest()
        self.logger.debug(f"Message hash: {h.hexdigest()}")
        return hashed


class CommandResponseMessage:
    def __init__(self, command_req_message, original_sqn, key, original_hash):
        self.logger = logging.getLogger(__name__)
        self.logger.info("command response init")
        self.original_hash = original_hash
        self.key = key
        self.type = b'\x01\x10'
        self.sqn = original_sqn
        self.payload = None
        self.message = command_req_message

    def command_response(self):
        self.logger.info("command response")
        self.payload = MTPResponseMessage(self.message, self.sqn, self.type, self.key).mtp_response()
        self.payload = self.payload.decode('utf-8')
        self.logger.debug(self.payload)
        if self.payload is None:
            return None, None
        payload_array = self.payload.split('\n')
        if bytes.fromhex(payload_array[1]) != self.original_hash:
            self.logger.error(f"Hashes do not match:\n"
                              f"Got: {payload_array[0]}\n"
                              f"expected: {self.original_hash}")
            return None, None
        return payload_array, (int.from_bytes(self.sqn, 'big') + 1).to_bytes(2, byteorder='big')


class UploadRequest0Message:
    def __init__(self, upload_req0_message, original_sqn, key):
        self.logger = logging.getLogger(__name__)
        self.logger.info("upload request0 init")
        self.key = key
        self.typ = b'\x02\x00'
        self.sqn = original_sqn
        self.payload = None
        self.message = upload_req0_message
        self.message = self.message.decode("utf-8")

    def send_file_fragment(self):
        self.logger.info("upload request0 function")
        return self.handle_message_to_mtp(), self.create_request_sha256()

    def handle_message_to_mtp(self):
        self.logger.info("upload request0 to mtp")
        return MTPRequestMessage(self.message, self.typ, self.sqn).create_request(self.key)

    def create_request_sha256(self):
        self.logger.info("file request sha256")
        print("Creating the SHA256 hash of the file...")
        h = SHA256.new()
        h.update(str.encode(self.message))
        hashed = h.digest()
        self.logger.debug(f"file hash: {h.hexdigest()}")
        return hashed


class UploadRequest1Message:
    def __init__(self, upload_req1_message, original_sqn, key):
        self.logger = logging.getLogger(__name__)
        self.logger.info("upload request1 init")
        self.key = key
        self.typ = b'\x02\x01'
        self.sqn = original_sqn
        self.payload = None
        self.message = upload_req1_message
        self.message = self.message.decode("utf-8")

    def send_file_last_fragment(self):
        self.logger.info("upload request1 function")
        return self.handle_message_to_mtp(), self.create_request_sha256()

    def handle_message_to_mtp(self):
        self.logger.info("upload request1 to mtp")
        return MTPRequestMessage(self.message, self.typ, self.sqn).create_request(self.key)

    def create_request_sha256(self):
        self.logger.info("file request sha256")
        print("Creating the SHA256 hash of the file...")
        h = SHA256.new()
        h.update(str.encode(self.message))
        hashed = h.digest()
        self.logger.debug(f"file hash: {h.hexdigest()}")
        return hashed


class UploadResponseMessage:
    def __init__(self, upload_res_message, original_sqn, key, original_hash):
        self.logger = logging.getLogger(__name__)
        self.logger.info("upload response init")
        self.original_hash = original_hash
        self.key = key
        self.type = b'\x02\x10'
        self.sqn = original_sqn
        self.payload = None
        self.message = upload_res_message

    def upload_response(self):
        self.logger.info("upload response")
        self.payload = MTPResponseMessage(self.message, self.sqn, self.type, self.key).mtp_response()
        self.payload = self.payload.decode('utf-8')
        self.logger.debug(self.payload)
        if self.payload is None:
            return None, None
        payload_array = self.payload.split('\n')
        self.logger.info("Hash check")
        if bytes.fromhex(payload_array[0]) != self.original_hash:
            self.logger.error(f"Hashes do not match:\n"
                              f"Got: {payload_array[0]}\n"
                              f"expected: {self.original_hash}")
            return None, None
        return payload_array


class DnloadRequestMessage:
    def __init__(self, download_req_message, original_sqn, key):
        self.logger = logging.getLogger(__name__)
        self.logger.info("download request init")
        self.key = key
        self.type = b'\x03\x00'
        self.sqn = original_sqn
        self.payload = None
        self.message = download_req_message

    def download_request(self):
        self.logger.info("download request to mtp")
        return MTPRequestMessage(self.message, self.type, self.sqn).create_request(self.key)


class DnloadResponseMessage:
    def __init__(self, download_res0_message, original_sqn, key):
        self.logger = logging.getLogger(__name__)
        self.logger.info("download response0 init")
        self.key = key
        self.type = b'\x03\x00'
        self.sqn = original_sqn
        self.payload = None
        self.message = download_res0_message

    def dnl_response(self):
        decrypt_download, last_fragment = MTPResponseMessage(self.message, self.sqn, self.type, self.key).decrypt_download()
        self.logger.debug(decrypt_download, last_fragment)
        return decrypt_download, last_fragment