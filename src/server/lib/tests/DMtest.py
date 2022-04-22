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