import random
from typing import Optional, Tuple

from Crypto.Util import number

PRIME_NUMBER_LENGTH_BITS = 16
SECRET_NUMBER_LENGTH_BITS = 8
RANDOM_NONCE_LENGTH_BITS = 8


def generate_random_num(n_bits: int):
    return number.getRandomNBitInteger(n_bits)


def generate_pq(p_bits: Optional[int] = PRIME_NUMBER_LENGTH_BITS) -> Tuple[int, int]:
    p = number.getPrime(p_bits)
    q = p // 2

    #while not number.isPrime(q):
    #    q += 1

    return p, q


def generate_g(p: int, q: int):
    g = random.randint(1, p - 1)
    while not pow(g, q) % p == 1:
        g = random.randint(1, p - 1)

    return g


def generate_gh(p: int, q: int) -> Tuple[int, int]:
    g1 = generate_g(p, q)
    g2 = generate_g(p, q)

    while g1 == g2:
        g2 = generate_g(p, q)

    return (g1, g2) if (g1 < g2) else (g2, g1)
