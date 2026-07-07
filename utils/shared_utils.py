import struct
import hashlib
from math import sqrt

import sage.all as sg
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler

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


def sample_discrete_gaussian_vector(sigma):
    """
        Sample a vector of length N(2D+1) from the discrete Gaussian distribution with standard deviation sigma
        (using Sage's DiscreteGaussianDistributionIntegerSampler). This is acceptable for prototyping, but not for
        production because it is susceptible to side-channel attacks.

        Args:
            sigma: standard deviation of the Gaussian distribution

        Returns:
            vector over ZZ
    """
    dim = N * (2 * D + 1)
    sampler = DiscreteGaussianDistributionIntegerSampler(sigma=sigma)
    return sg.vector(sg.ZZ, [sampler() for _ in range(dim)])


def sample_randomness(sigma):
    """
        Sample a vector of length N(2D+1) whose components are polynomials in Rq. The coefficients of each polynomial
        are drawn from a discrete Gaussian distribution with standard deviation sigma.

        Args:
            sigma: standard deviation of the Gaussian distribution

        Returns:
            vector over Rq
    """
    coeffs_list = sample_discrete_gaussian_vector(sigma).list()

    chunks = [coeffs_list[i:i + N] for i in range(0, len(coeffs_list), N)]
    r_polys = [Rq(chunk) for chunk in chunks]

    return sg.vector(Rq, r_polys)


def hash_to_challenge(c, t0, t1):
    """
        Fiat-Shamir hash function using SHAKE256 as a proper Extendable-Output Function (XOF)
        that maps the given args to a permutation π = (perm, signs).
        This implements the challenge space Π = Perm(n) × {0,1}^60.

        Args:
            c: commitment vector
            t0, t1: vectors over Rq, as computed in the OR-proof

        Returns:
            a permutation of 0..N-1
            a list of 60 booleans (sign flips)
    """
    # Serialize inputs
    data = b"OR_PROOF:" + serialize_rq_vector(c) + serialize_rq_vector(t0) + serialize_rq_vector(t1)

    # SHAKE256 instance
    shake = hashlib.shake_256()
    shake.update(data)

    # Total bytes needed: N * 4 for indices + 8 for sign bits
    total_bytes = N * 4 + 8
    all_bytes = shake.digest(total_bytes)

    # Split the digest
    random_bytes = all_bytes[:N * 4]  # for permutation
    sign_bytes = all_bytes[N * 4:]  # for signs

    # Generate permutation with Fisher-Yates algorithm
    perm = list(range(N))
    for i in range(N - 1, -1, -1):
        rand_val = struct.unpack('<I', random_bytes[i * 4:(i + 1) * 4])[0]
        j = rand_val % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]

    # Extract 60 sign bits
    bits = struct.unpack('<Q', sign_bytes)[0]
    signs = [((bits >> k) & 1) == 1 for k in range(60)]

    return perm, signs


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
