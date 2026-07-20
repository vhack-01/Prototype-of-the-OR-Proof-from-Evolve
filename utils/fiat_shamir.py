import hashlib
import struct

from utils.shared_utils import serialize_rq_vector
from config.params import N
from config.ring import Rq


# --------------------------------------------------------
#  Fiat-Shamir
# --------------------------------------------------------

def hash_to_challenge(c, t0, t1):
    """
        Fiat-Shamir hash function using SHAKE256 as a proper eXtendable-Output Function (XOF)
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


def apply_challenge(poly, perm, signs, inverse=False):
    """
    Apply a permutation and sign flips to the coefficients of a polynomial,
    or apply the inverse if inverse=True.

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

    new_coeffs = [0] * N

    if not inverse:
        # Forward: π(f)
        rank = {pos: idx for idx, pos in enumerate(sorted(non_zero_positions))}

        for i, c in enumerate(coeffs):
            if c != 0:
                new_idx = perm[i]  # get the index that the value should be moved to
                flip = -1 if signs[rank[i]] else 1  # flip sign if the corresponding bit is set
                new_coeffs[new_idx] = c * flip  # save new value in its new location
    else:
        # Inverse: recover f from g = π(f)
        inv_perm = [0] * N

        for i, p in enumerate(perm):
            inv_perm[p] = i

        original_positions = [inv_perm[q] for q in non_zero_positions]
        sorted_original = sorted(original_positions)
        pos_to_idx = {p: idx for idx, p in enumerate(sorted_original)}

        for q, c in zip(non_zero_positions, [coeffs[q] for q in non_zero_positions]):
            p = inv_perm[q]
            k = pos_to_idx[p]
            flip = -1 if signs[k] else 1
            new_coeffs[p] = c * flip

    return Rq(new_coeffs)
