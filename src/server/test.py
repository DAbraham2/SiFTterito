import time
import unittest
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from lib.cryptoStuff import decryptLoginRequestEPD
from lib.constants import MTPConstants


def getHeader(epd, sqn, rnd) -> bytes:
    ver = bytes.fromhex('01 00')
    typ = MTPConstants.LoginRequestType
    length = 16 + len(epd) + 12 + 256
    _len = length.to_bytes(2, 'big')
    rsv = bytes.fromhex('00 00')
    return ver+typ+_len+sqn+rnd+rsv


class TestEPDecrypt(unittest.TestCase):
    def test(self):
        tk = get_random_bytes(32)
        rnd = get_random_bytes(6)
        sqn = bytes.fromhex('00 01')
        nonce = sqn + rnd
        
        pd = bytes('{}\nalice\naaa\n{}'.format( time.time_ns(), get_random_bytes(16).hex()), 'utf-8')
        header = getHeader(pd, sqn, rnd)
        self.assertEqual(len(header), 16)

        cipher = AES.new(tk, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipher.update(header)
        epd, mac= cipher.encrypt_and_digest(pd)
        
        with open('example.bin', 'wb') as f:
            f.write(header+epd+mac)
            f.flush()
            f.close()

        decriptedContent = decryptLoginRequestEPD(epd+mac,getHeader(pd, sqn, rnd), tk, rnd, sqn)

        self.assertEqual(decriptedContent, pd)

if __name__ == "__main__":
    unittest.main()