from zkp_auth.sigma_protocols import utils


class ChaumPedersenVerifier:

    def __init__(self, p, g: int, h: int, y1: int, y2: int, r1: int, r2: int):
        """
        Constructor to initialise verifier instance with provers commitment
        @TODO: Refactor this constructor using builder pattern!
        :param p: prime number from prover
        :param g: generator number 1
        :param h: generator number 2
        :param y1: public information
        :param y2: public information
        :param r1: commitment
        :param r2: commitment
        """
        self.p = p
        self.g = g
        self.h = h
        self.y1 = y1
        self.y2 = y2
        self.r1 = r1
        self.r2 = r2
        self.c = utils.generate_random_num(utils.RANDOM_NONCE_LENGTH_BITS)

    def __str__(self):
        return f"""
        ChaumPedersenProver:
            p: {self.p}
            g: {self.g}
            h: {self.h}
            y1: {self.y1}
            y2: {self.y2}
            r1: {self.r1}
            r2: {self.r2}
            c: {self.c}
        """

    def get_challenge(self):
        return self.c

    def verify(self, s: int):
        res1 = (pow(self.g, s) * pow(self.y1, self.c)) % self.p
        res2 = (pow(self.h, s) * pow(self.y2, self.c)) % self.p
        return res1 == self.r1 and res2 == self.r2
