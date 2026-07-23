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

    # Set up SHAKE256 instance
    shake = hashlib.shake_256()
    shake.update(data)

    # Total bytes needed: N * 4 for indices + 8 for sign bits
    all_bytes = shake.digest(N * 4 + 8)

    # Split the digest
    permutation_bytes = all_bytes[:N * 4]
    sign_bytes = all_bytes[N * 4:]

    # Generate permutation (Fisher-Yates)
    perm = list(range(N))  # initialize identity permutation
    for i in range(N - 1, -1, -1):
        # extract 4 bytes as unsigned 32-bit integer
        rand_val = struct.unpack('<I', permutation_bytes[i * 4:(i + 1) * 4])[0]

        # reduce the integer modulo (i + 1), so that it falls into [0, i]
        j = rand_val % (i + 1)

        # in-place swap the elements at i and j
        perm[i], perm[j] = perm[j], perm[i]

    # Generate 60 sign bits
    bits = struct.unpack('<Q', sign_bytes)[0]  # extract 8 bytes as unsigned 64-bit integer
    signs = [((bits >> k) & 1) == 1 for k in range(60)]  # check if k-th bit is 1; ignore last 4 bits

    return perm, signs


def apply_challenge(poly, perm, signs, inverse=False):
    """
    Apply a permutation and sign flips to the coefficients of a polynomial,
    or apply the inverse if inverse=True.

    Args:
        poly: a challenge polynomial from the challenge space
        perm: permutation of indices 0..N-1
        signs: list of 60 booleans, True means flip the sign of the i-th nonzero coefficient
        inverse: if True, apply the inverse permutation; if False (default), apply the forward permutation.

    Returns:
        the transformed polynomial
    """
    coeffs = poly.list()
    nonzero_positions = [i for i, c in enumerate(coeffs) if c != 0]
    assert len(nonzero_positions) == 60, f"Expected 60 nonzero coefficients, got {len(nonzero_positions)}"

    new_coeffs = [0] * N

    if not inverse:  # Forward: π(f)
        # flip and permute
        for idx, pos in enumerate(nonzero_positions):
            flip = -1 if signs[idx] else 1
            new_coeffs[perm[pos]] = coeffs[pos] * flip

    else:  # Inverse: recover f from g = π(f)
        # invert permutation
        inv_perm = [0] * N
        for idx, pos in enumerate(perm):
            inv_perm[pos] = idx

        # get original nonzero positions
        original_nonzero_positions = sorted(inv_perm[q] for q in nonzero_positions)

        # permute and flip
        for idx, pos in enumerate(original_nonzero_positions):
            flip = -1 if signs[idx] else 1
            new_coeffs[pos] = coeffs[perm[pos]] * flip

    return Rq(new_coeffs)
