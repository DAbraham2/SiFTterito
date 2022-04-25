from lib.DirectoryManager import DirManager
import unittest

s = 'success'
f = 'failure'

class DirManagementTest(unittest.TestCase):
    def testNonExistantFolder(self):
        b = DirManager('TestUser')
        res = b.chd('feri')
        self.assertEqual(f, res)
    
    def test_EscapeHome(self):
        b = DirManager('TestUser')
        res = b.chd('..')
        self.assertEqual(f, res)

    def test_ChangeDir(self):
        b = DirManager('TestUser')
        res = b.chd('test')
        self.assertEqual(s, res)

    def test_EscapeDir(self):
        b = DirManager('TestUser')
        res = b.chd('test/../../..')
        self.assertEqual(f, res)

    def test_Pwd(self):
        b = DirManager('TestUser')
        res = b.pwd()
        self.assertEqual('~/', res)

    def test_Pwd2(self):
        b = DirManager('TestUser')
        b.chd('test')
        res = b.pwd()
        self.assertTrue(res.endswith('test'))

    def test_Lst1(self):
        b = DirManager('TestUser')
        res = b.lst()
        self.assertTrue(res.startswith('success'))
        self.assertFalse(res.find('fer.txt') is -1)
        self.assertFalse(res.find('test') is -1)