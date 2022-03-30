import unittest

from zkp_auth.sigma_protocols import utils
from zkp_auth.sigma_protocols.chaum_pedersen.prover import ChaumPedersenProver


class TestChaumPedersenProver(unittest.TestCase):

    def test_init(self):
        ch_prover = ChaumPedersenProver(
            secret_x=6,
            p=23,
            q=11,
            g=4,
            h=9,
            k=7
        )
        print(ch_prover)

        self.assertEqual(ch_prover.secret_x, 6)
        self.assertEqual(ch_prover.p, 23)
        self.assertEqual(ch_prover.q, 11)
        self.assertEqual(ch_prover.g, 4)
        self.assertEqual(ch_prover.h, 9)
        self.assertEqual(ch_prover.k, 7)

    def test_init_random(self):
        ch_prover = ChaumPedersenProver()
        print(ch_prover)

        self.assertGreater(ch_prover.secret_x, 0)
        self.assertGreater(ch_prover.p, 0)
        self.assertGreater(ch_prover.q, 0)
        self.assertGreater(ch_prover.g, 0)
        self.assertGreater(ch_prover.h, 0)
        self.assertGreater(ch_prover.k, 0)

    def test_compute_y1y2(self):
        ch_prover = ChaumPedersenProver()
        y1, y2 = ch_prover.compute_y1y2()
        print(y1, y2)

        self.assertGreater(y1, 0)
        self.assertGreater(y2, 0)

    def test_compute_commitment(self):
        ch_prover = ChaumPedersenProver(
            secret_x=6,
            p=23,
            q=11,
            g=4,
            h=9,
            k=7
        )
        r1, r2 = ch_prover.compute_commitment()
        print(r1, r2)

        self.assertEqual((8, 4), (r1, r2))

    def test_compute_commitment_random(self):
        ch_prover = ChaumPedersenProver()
        r1, r2 = ch_prover.compute_commitment()
        print(r1, r2)

        self.assertGreater(r1, 0)
        self.assertGreater(r2, 0)

    def test_prove(self):
        ch_prover = ChaumPedersenProver(
            secret_x=6,
            p=23,
            q=11,
            g=4,
            h=9,
            k=7
        )
        s = ch_prover.prove(4)

        self.assertEqual(s, 5)

    def test_prove_random(self):
        ch_prover = ChaumPedersenProver()
        s = ch_prover.prove(utils.generate_random_num(utils.RANDOM_NONCE_LENGTH_BITS))
        print(s)

        self.assertGreater(s, 0)


if __name__ == '__main__':
    import xmlrunner

    unittest.main(testRunner=xmlrunner.XMLTestRunner(output='test-reports'))
