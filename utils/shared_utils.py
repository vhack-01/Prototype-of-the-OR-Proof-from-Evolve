import struct
from math import sqrt

from config.params import N


# --------------------------------------------------------
#  Helper functions for the Commitment, Prover and Verifier
# --------------------------------------------------------


def norm_rq_vector(vec):
    """
        Compute the Euclidean norm of a vector of polynomials in Rq

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
