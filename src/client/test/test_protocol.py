import unittest
import sys

sys.path.append('../../protocol')
import SiFT_MTP
from Crypto import Random
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, PKCS1_OAEP


class MTPRequestTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_calc_message_len(self):
        self.assertEqual(True, False)  # add assertion here

    def test_calc_login_len(self):
        self.assertEqual(True, False)  # add assertion here

    def test_create_header(self):
        self.assertEqual(True, False)  # add assertion here

    def test_create_request(self):
        self.assertEqual(True, False)  # add assertion here

    def test_login_req(self):
        self.assertEqual(True, False)  # add assertion here

    def test_generate_mac(self):
        self.assertEqual(True, False)  # add assertion here

    def test_message_encription(self):
        self.assertEqual(True, False)  # add assertion here

    def test_encrypt_first_message(self):
        self.assertEqual(True, False)  # add assertion here


class MTPResponseTest(unittest.TestCase):
    def setUp(self):
        key = Random.get_random_bytes(32)
        res_type = b"\x00\x10"
        req_sqn = b"\x00\x01"
        message = "this is a test message"  # 22
        random_six = Random.get_random_bytes(6)
        nonce = b"\x00\x02" + random_six
        ENC = AES.new(key, AES.MODE_GCM, nonce)
        encrypted_payload = None
        try:
            encrypted_payload = ENC.encrypt(message.encode('utf-8'))
        except Exception as e:
            print(e)
        print(len(encrypted_payload))
        self.header = b"\x01\x00" + \
                      res_type + \
                      (50).to_bytes(2, 'big') + \
                      b"\x00\x02" + \
                      random_six + \
                      b"\x00\x00"
        cipehr = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipehr.update(self.header)
        cipehr.update(encrypted_payload)
        mac = cipehr.digest()
        print(mac)
        test_payload = self.header + encrypted_payload + mac
        print(test_payload)
        self.mtp = SiFT_MTP.MTPResponseMessage(test_payload, req_sqn, res_type, key)

    def test_version_check(self):
        with self.subTest():
            self.assertFalse(self.mtp.check_version(b'\x01\x01'))
        with self.subTest():
            self.assertTrue(self.mtp.check_version(b'\x01\x00'))

    def test_length_check(self):
        with self.subTest():
            self.assertFalse(self.mtp.check_length(b'\x01\x51'))
        with self.subTest():
            self.assertTrue(self.mtp.check_length(b'\x01\x50'))

    def test_sqn_check(self):
        with self.subTest():
            self.assertFalse(self.mtp.check_sqn(b'\x00\x01', b"\x00\x01"))
        with self.subTest():
            self.assertTrue(self.mtp.check_sqn(b'\x00\x02', b"\x00\x01"))

    def test_type_check(self):
        with self.subTest():
            self.assertFalse(self.mtp.check_type(b'\x00\x01', b"\x00\x10"))
        with self.subTest():
            self.assertTrue(self.mtp.check_type(b'\x00\x10', b"\x00\x10"))

    def test_mtp_response(self):
        self.assertEqual(self.mtp.mtp_response(), "")


class LoginResponseTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_parsed_message(self):
        self.assertEqual(self.log_res.parse_message(), ("", ""))  # add assertion here


class LoginRequestTest(unittest.TestCase):
    def setUp(self):
        pass

    def test_login_request(self):
        self.assertEqual(True, False)  # add assertion here

    def test_create_sha256(self):
        self.assertEqual(True, False)  # add assertion here

    def test_handle_message_to_mtp(self):
        self.assertEqual(True, False)  # add assertion here

    def test_create_mtp_message(self):
        self.assertEqual(True, False)  # add assertion here

    def test_public_key_load(self):
        self.assertEqual(True, False)  # add assertion here


class CommandResponseTest(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)  # add assertion here


class CommandRequestTest(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)  # add assertion here


class UploadRequestTest(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)  # add assertion here


class UploadResponseTest(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)  # add assertion here


class DownloadRequestTest(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)  # add assertion here


class DownloadResponseTest(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)  # add assertion here


if __name__ == '__main__':
    unittest.main()
