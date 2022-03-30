import unittest

from zkp_auth.sigma_protocols.chaum_pedersen.prover import ChaumPedersenProver
from zkp_auth.sigma_protocols.chaum_pedersen.verifier import ChaumPedersenVerifier


class TestChaumPedersenProverWithVerifier(unittest.TestCase):

    def test_prove_and_verify(self):

        print("\n---> Prover: Initialising ChaumPedersenProver")
        ch_prover = ChaumPedersenProver()
        y1, y2 = ch_prover.compute_y1y2()
        r1, r2 = ch_prover.compute_commitment()

        print("---> Prover: Sending public info and commitment to: ChaumPedersenVerifier")

        verifier_params = {
            'p': ch_prover.p,
            'g': ch_prover.g,
            'h': ch_prover.h,
            'y1': y1,
            'y2': y2,
            'r1': r1,
            'r2': r2
        }

        print(verifier_params)

        print("---> Verifier: Received public info and commitment. Initialising ChaumPedersenVerifier...")
        ch_verifier = ChaumPedersenVerifier(**verifier_params)

        print("---> Verifier: Created challenge and sending to Prover...")
        c = ch_verifier.get_challenge()
        print(c)

        print("---> Prover: Received challenge! Computing response and sending back to Verifier")
        s = ch_prover.prove(c)
        print(s)

        print("---> Verifier: Received response. Verifying...")
        is_valid = ch_verifier.verify(s)
        print(is_valid)

        print(f"---> Verifier: {'Response is valid!' if is_valid else 'Response is not valid!!!'}")
        self.assertTrue(is_valid, "Verify should return True")


if __name__ == '__main__':
    import xmlrunner

    unittest.main(testRunner=xmlrunner.XMLTestRunner(output='test-reports'))
