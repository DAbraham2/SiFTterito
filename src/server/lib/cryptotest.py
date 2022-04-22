import unittest

from lib.cryptoStuff import loginFunction


class LoginTest(unittest.TestCase):
    def test(self):
        s = 'alice\t{}\t{}\n'.format('6dc5d073d7636eb57970de38982a4573512c87d17586af2540c94e2a88dc6db3bc73176625202f0530939e7f64800ddd035a11fa41c595b4aeba60e35ae2b34a79d3ec8c7ef9557fb5c4f01bd7dd7896fd92d776e473e88b477bba670292c7755967f45ed9c699d02c69efd49ac87213153fd33b93253bb580410c90588d346a',
                                     'ac91e32a690d701b6d2ed34da08c24a9757b5b253e0fab27d49577f1e0c2e320')
        with open('users.passwd', 'wt') as f:
            f.write(s)
            f.flush()
            f.close()
        result = loginFunction('alice', 'WonDerLanD')
        self.assertEqual(result, True)
