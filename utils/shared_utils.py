import struct
from math import sqrt
import secrets

from config.params import N, Q, N_A

# --------------------------------------------------------
#  Helper functions for the Commitment, Prover and Verifier
# --------------------------------------------------------

SECURE_RNG = secrets.SystemRandom()  # instantiate a cryptographically secure random number generator


def norm_rq_vector(vec):
    """
        Compute the Euclidean norm of a vector of polynomials in Rq, using the centered representation of coefficients

        Args:
            vec: vector over Rq

        Returns:
            Euclidean norm of vec
    """
    return sqrt(sum(c.lift_centered() ** 2 for poly in vec for c in poly.list()))


def serialize_rq_vector(vec):
    """
        Serialize a vector of polynomials in Rq to bytes (little-endian signed 32-bit ints)

        Args:
            vec: vector over Rq

        Returns:
            concatenated bytes of each polynomial
    """
    parts = []
    for poly in vec:
        parts.append(struct.pack('<' + 'i' * N, *[int(c.lift_centered()) for c in poly.list()]))
    return b''.join(parts)


def split_vote(v_i):
    """
    Splits a vote v_i (should 0 or 1) into N_A additive shares modulo Q.

    Args:
        v_i: The vote

    Returns:
        A list of N_A integers, each in [0, Q-1].
        The sum of these shares modulo Q equals v_i.
    """
    shares = []

    # Generate the first N_A - 1 shares uniformly at random modulo Q
    for _ in range(N_A - 1):
        share = SECURE_RNG.randrange(Q)  # picks an integer from 0 to Q-1 inclusive
        shares.append(share)

    # Compute the final share so that total_sum ≡ v_i (mod Q)
    last_share = (v_i - sum(shares)) % Q
    shares.append(last_share)

    return shares
