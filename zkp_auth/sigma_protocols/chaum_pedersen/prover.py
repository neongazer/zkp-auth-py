from typing import Tuple, Optional

from zkp_auth.sigma_protocols import utils


class ChaumPedersenProver:

    def __init__(self,
                 secret_x: Optional[int] = None,
                 p: Optional[int] = None,
                 q: Optional[int] = None,
                 g: Optional[int] = None,
                 h: Optional[int] = None,
                 k: Optional[int] = None,
                 strength_bits: Optional[int] = utils.SECRET_NUMBER_LENGTH_BITS
                 ):

        self.secret_x = secret_x if secret_x else utils.generate_random_num(strength_bits)

        if p and q:
            self.p, self.q = p, q
        else:
            self.p, self.q = utils.generate_pq()

        if g and h:
            self.g, self.h = g, h
        else:
            self.g, self.h = utils.generate_gh(self.p, self.q)

        self.k = k if k else utils.generate_random_num(utils.RANDOM_NONCE_LENGTH_BITS)

    def __str__(self):
        return f"""
        ChaumPedersenProver:
            p: {self.p}
            q: {self.q}
            g: {self.g}
            h: {self.h}
            k: {self.k}
        """

    def compute_y1y2(self) -> Tuple[int, int]:
        """
        Algorithm used to compute the public y1, y2
        :return: tuple(y1, y2)
        """
        return (
            pow(self.g, self.secret_x) % self.p,
            pow(self.h, self.secret_x) % self.p
        )

    def compute_commitment(self):
        """
        R(x,k) - algorithm used to compute the commitment r
        :return: int commitment r
        """
        return (
            pow(self.g, self.k) % self.p,
            pow(self.h, self.k) % self.p
        )

    def prove(self, c: int) -> int:
        """
        S(c,x,k) - algorithm which prover uses to compute their response s
        :param c: int challenge from verifier
        :return: int response
        """
        return (self.k - c * self.secret_x) % self.q

