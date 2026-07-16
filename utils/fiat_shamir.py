import hashlib
import struct

from utils.shared_utils import serialize_rq_vector
from config.params import N


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
