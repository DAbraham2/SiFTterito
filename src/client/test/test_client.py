import unittest
import sys
import io

sys.path.insert(1, '/client')
sys.path.append('../')
import SiFTClient
import dummy_server

from unittest.mock import patch


class CommandFormatTest(unittest.TestCase):
    def setUp(self):
        host = "localhost"
        port = 5150
        self.client = SiFTClient.SiFTClient(host, port, "public_bp.pem")

    def test_pwd_format(self):
        test_input = ['pwd']
        expected = 'pwd'
        self.assertEqual(self.client.command_format(test_input), expected)

    def test_lst_format(self):
        test_input = ["lst"]
        expected = 'lst'
        self.assertEqual(self.client.command_format(test_input), expected)

    def test_chd_format(self):
        test_input = ['chd', 'testdir']
        expected = 'chd\ntestdir'
        self.assertEqual(self.client.command_format(test_input), expected)

    def test_mkd_format(self):
        test_input = ["mkd", "testdir"]
        expected = 'mkd\ntestdir'
        self.assertEqual(self.client.command_format(test_input), expected)

    def test_del_format(self):
        test_input = ['del', 'testfile']
        expected = 'del\ntestfile'
        self.assertEqual(self.client.command_format(test_input), expected)

    def test_upl_format(self):
        test_input = ['upl', 'testfile']
        expected = 'upl\ntestfile\n11\nd5579c46dfcc7f18207013e65b44e4cb4e2c2298f4ac457ba8f82743f31e930b'
        self.assertEqual(self.client.command_format(test_input), expected)

    def test_dnl_format(self):
        test_input = ['dnl', 'testfile']
        expected = 'dnl\ntestfile'
        self.assertEqual(self.client.command_format(test_input), expected)


class UITest(unittest.TestCase):
    def setUp(self):
        host = "localhost"
        port = 5150
        self.client = SiFTClient.SiFTClient(host, port, "public_bp.pem")

    def test_validate_false(self):
        self.assertFalse(self.client.ui.validate("", "test name"))

    def test_validate_true(self):
        self.assertTrue(self.client.ui.validate('test', "test name"))

    @patch('builtins.input', side_effect=['n'])
    def test_makesure_window_false(self, mock_input):
        self.assertFalse(self.client.ui.make_sure_window(mock_input))

    @patch('builtins.input', side_effect=['y'])
    def test_makesure_window_true(self, mock_input):
        self.assertTrue(self.client.ui.make_sure_window(mock_input))

    @patch('builtins.input', side_effect=['username1', 'password0'])
    def test_login_window(self, mock_input):
        # with unittest.mock.patch('builtins.input', return_value=['username', 'password']):
        self.assertEqual(self.client.ui.login_window(False), ("username1", "password0"))


class ConnectionTest(unittest.TestCase):
    '''
    This test needs the dummy server to run
    '''

    def setUp(self):
        host = "localhost"
        port = 5150
        self.client = SiFTClient.SiFTClient(host, port, "public_bp.pem")
        self.wrong_client = SiFTClient.SiFTClient(host, 5151, "public_bp.pem")

    def test_connection(self):
        sock = self.client.connect()
        self.assertNotEqual(sock, None)


class FunctionTest(unittest.TestCase):
    def setUp(self):
        host = "localhost"
        port = 5150
        self.client = SiFTClient.SiFTClient(host, port, "public_bp.pem")

    def test_sqn_increase(self):
        expected_sqn = b'\x00\x03'
        self.client.increase_sqn()
        self.client.increase_sqn()
        self.client.increase_sqn()
        self.assertEqual(self.client.sqn, expected_sqn)

    def test_final_key_generation(self):
        test_hash_salt = b"919963f263c2d6889fb91f9fea17abc5f11aa112b9a46a71c3e179ae43c617d3" # chd\ntestdir
        test_client_random = b"2e8a328f25fc089cffecf961e72f3ae7"
        test_server_random = b"683b91a170308675b175126213f0c0b3"
        self.client.generate_final_key(test_client_random, test_server_random, test_hash_salt)
        self.assertEqual(self.client.final_key.hex(), "e6f3f5b53481252277d532ef568068f11397bc403c16787a3751e0978ad14ed0")


if __name__ == '__main__':
    unittest.main()
