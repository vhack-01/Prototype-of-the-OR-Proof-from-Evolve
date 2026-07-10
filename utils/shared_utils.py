import struct
import hashlib
from math import sqrt

from config.params import D, N, Q
from config.ring import Rq


# --------------------------------------------------------
#  Helper functions for the Commitment, Prover and Verifier
# --------------------------------------------------------

def center_coefficient(c):
    """
        Convert a ring element coefficient to its centered representative modulo Q (EVOLVE paper section 2.1 states that
        integers modulo q will be represented between -⌊(Q-1)/2⌋ and +⌊(Q+1)/2⌋).

        Args:
            c: a ring element

        Returns:
            the centered integer representative of c
    """
    half_q = (Q + 1) // 2  # = +⌊(Q+1)/2⌋)
    c_int = c.lift()  # returns the integer representation of c between 0 and Q-1
    return c_int if c_int <= half_q else c_int - Q  # center c if needed


def apply_permutation(poly, perm, signs, inverse=False):
    """
    Apply a permutation (and sign flips) to the coefficients of a polynomial,
    or apply its inverse if inverse=True.

    Args:
        poly: a challenge polynomial from the challenge space
        perm: permutation of indices 0..N-1 (π)
        signs: list of 60 booleans, True means flip the sign of the i-th non-zero coefficient
        inverse: if True, apply the inverse permutation; if False, apply the forward permutation.

    Returns:
        the transformed polynomial
    """
    coeffs = poly.list()
    non_zero_positions = [i for i, c in enumerate(coeffs) if c != 0]
    assert len(non_zero_positions) == 60, f"Expected 60 non-zero coefficients, got {len(non_zero_positions)}"

    if not inverse:
        # Forward: π(f)
        rank = {pos: idx for idx, pos in enumerate(sorted(non_zero_positions))}
        new_coeffs = [0] * N
        for i, c in enumerate(coeffs):
            if c != 0:
                new_idx = perm[i]
                flip = -1 if signs[rank[i]] else 1
                new_coeffs[new_idx] = c * flip
    else:
        # Inverse: recover f from g = π(f)
        inv_perm = [0] * N
        for i, p in enumerate(perm):
            inv_perm[p] = i
        original_positions = [inv_perm[q] for q in non_zero_positions]
        sorted_original = sorted(original_positions)
        pos_to_idx = {p: idx for idx, p in enumerate(sorted_original)}
        new_coeffs = [0] * N
        for q, c in zip(non_zero_positions, [coeffs[q] for q in non_zero_positions]):
            p = inv_perm[q]
            k = pos_to_idx[p]
            flip = -1 if signs[k] else 1
            new_coeffs[p] = c * flip

    return Rq(new_coeffs)


def serialize_rq_vector(vec):
    """
        Serialize a vector of polynomials in Rq to bytes (little-endian signed 32-bit ints)

        Args:
            vec: vector over Rq

        Returns:
            concatenated bytes of each polynomial
    """
    data = b''
    for poly in vec:
        data += struct.pack('<' + 'i' * N, *[int(center_coefficient(c)) for c in poly.list()])
    return data


def norm_rq_vector(vec):
    """
        Compute the Euclidean norm of a vector of polynomials in Rq

        Args:
            vec: vector over Rq

        Returns:
            Euclidean norm of vec
    """
    return sqrt(sum(center_coefficient(c) ** 2 for poly in vec for c in poly.list()))
