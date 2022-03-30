import unittest

from Crypto.Util import number

from zkp_auth.sigma_protocols.utils import generate_pq, generate_g, generate_gh, generate_random_num


class TestUtils(unittest.TestCase):

    def test_generate_random_num(self):

        for i in range(1, 12):
            len = pow(2, i)
            x = generate_random_num(len)
            self.assertEqual(x.bit_length(), len)

    def test_generate_pq(self):

        p, q = generate_pq(2)
        self.assertEqual(p.bit_length(), 2)
        self.assertEqual((p, q), (3, 1))

        p, q = generate_pq(3)
        self.assertEqual(p.bit_length(), 3)
        self.assertIn((p, q), [(3, 2), (5, 2), (7, 2), (7, 3)])

        num_tries = 0
        while num_tries < 1000:
            num_tries += 1
            p, q = generate_pq(16)
            print(p, q)
            self.assertEqual(p.bit_length(), 16)
            self.assertTrue(number.isPrime(p))

        num_tries = 0
        while num_tries < 100:
            num_tries += 1
            p, q = generate_pq(32)
            print(p, q)
            self.assertEqual(p.bit_length(), 32)
            self.assertTrue(number.isPrime(p))

    def test_generate_pq_1024(self):
        p, q = generate_pq(1024)
        print(p, q)
        self.assertEqual(p.bit_length(), 1024)
        self.assertTrue(number.isPrime(p))

    def test_generate_pq_2048(self):
        p, q = generate_pq(2048)
        print(p, q)
        self.assertEqual(p.bit_length(), 2048)
        self.assertTrue(number.isPrime(p))

    def test_generate_g(self):
        p, q = generate_pq()
        g = generate_g(p, q)

        print(p, q, g)

        self.assertEqual(pow(g, q) % p, 1)

    def test_generate_gh(self):
        p, q = generate_pq()
        g, h = generate_gh(p, q)

        print(p, q, g, h)

        self.assertEqual(pow(g, q) % p, 1)
        self.assertEqual(pow(h, q) % p, 1)


if __name__ == '__main__':
    import xmlrunner

    unittest.main(testRunner=xmlrunner.XMLTestRunner(output='test-reports'))
