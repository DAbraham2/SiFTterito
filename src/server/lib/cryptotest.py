from Crypto.Protocol.KDF import scrypt
import unittest

from numpy import result_type
from lib.constants import get_base_folder

from lib.cryptoStuff import loginFunction

from Crypto.Random import get_random_bytes


class LoginTest(unittest.TestCase):
    def test(self):
        result = loginFunction('alice', 'aaa')
        self.assertTrue(result)

    def test2(self):
        result = loginFunction('bob', 'bbb')
        self.assertTrue(result)

    def test3(self):
        result = loginFunction('charlie', 'ccc')
        self.assertTrue(result)
