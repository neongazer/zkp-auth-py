import unittest

from zkp_auth.sigma_protocols.chaum_pedersen.prover import ChaumPedersenProver
from zkp_auth.sigma_protocols.chaum_pedersen.verifier import ChaumPedersenVerifier


class TestChaumPedersenVerifier(unittest.TestCase):

    def test_init(self):

        ch_prover = ChaumPedersenProver(
            secret_x=6,
            p=23,
            q=11,
            g=4,
            h=9,
            k=7
        )
        y1, y2 = ch_prover.compute_y1y2()
        r1, r2 = ch_prover.compute_commitment()

        verifier_params = {
            'p': ch_prover.p,
            'g': ch_prover.g,
            'h': ch_prover.h,
            'y1': y1,
            'y2': y2,
            'r1': r1,
            'r2': r2
        }
        ch_verifier = ChaumPedersenVerifier(**verifier_params)
        print(ch_verifier)

        self.assertEqual(ch_verifier.p, 23)
        self.assertEqual(ch_verifier.g, 4)
        self.assertEqual(ch_verifier.h, 9)
        self.assertEqual(ch_verifier.y1, 2)
        self.assertEqual(ch_verifier.y2, 3)
        self.assertEqual(ch_verifier.r1, r1)
        self.assertEqual(ch_verifier.r2, r2)
        self.assertGreater(ch_verifier.c, 0)

    def test_init_random(self):

        ch_prover = ChaumPedersenProver()
        y1, y2 = ch_prover.compute_y1y2()
        r1, r2 = ch_prover.compute_commitment()

        verifier_params = {
            'p': ch_prover.p,
            'g': ch_prover.g,
            'h': ch_prover.h,
            'y1': y1,
            'y2': y2,
            'r1': r1,
            'r2': r2
        }
        ch_verifier = ChaumPedersenVerifier(**verifier_params)
        print(ch_verifier)

        self.assertGreater(ch_verifier.p, 0)
        self.assertGreater(ch_verifier.g, 0)
        self.assertGreater(ch_verifier.h, 0)
        self.assertGreater(ch_verifier.y1, 0)
        self.assertGreater(ch_verifier.y2, 0)
        self.assertGreater(ch_verifier.r1, 0)
        self.assertGreater(ch_verifier.r2, 0)
        self.assertGreater(ch_verifier.c, 0)


if __name__ == '__main__':
    import xmlrunner

    unittest.main(testRunner=xmlrunner.XMLTestRunner(output='test-reports'))
