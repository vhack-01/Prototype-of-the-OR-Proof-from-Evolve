import sage.all as sg

from config.params import D, Q, B_OR_PRIME
from config.ring import Rq
from utils.shared_utils import apply_permutation, norm_rq_vector
from utils.fiat_shamir import hash_to_challenge


# --------------------------------------------------------
#  OR-Proof - Verifier (EVOLVE paper section 3.2, Verify_{OR} algorithm)
# --------------------------------------------------------

def verify_or_proof(C, c, r0, r1, f0, f1):
    """
    Verify an OR-proof for the commitment c.

    Args:
        C: public commitment key
        c: commitment vector
        r0, r1: response vectors
        f0, f1: challenge polynomials

    Returns:
        True if the proof is valid, False otherwise.
    """
    # (1) Compute t0
    t0 = C * r0 - f0 * c

    # (2) Compute t1
    vec = sg.vector(Rq, [0] * D + [1])
    t1 = C * r1 + f1 * vec - f1 * c

    # (3) Recompute challenge π
    perm, signs = hash_to_challenge(c, t0, t1)

    # (4) + (5) Check norm bounds
    r0_norm = norm_rq_vector(r0)
    r1_norm = norm_rq_vector(r1)

    if r0_norm > B_OR_PRIME or r1_norm > B_OR_PRIME:
        return False

    # (6) Check if f0 belongs to the challenge set
    if not is_valid_challenge_polynomial(f0):
        return False

    # (7) Check f1 = π(f0)
    f1_computed = apply_permutation(f0, perm, signs, False)
    if f1 != f1_computed:
        return False

    # All checks passed
    return True


# --------------------------------------------------------
#  Helper Functions for the Verifier
# --------------------------------------------------------

def is_valid_challenge_polynomial(f):
    """
        Check that f is a valid challenge polynomial (has exactly 60 non-zero coefficients, each being in {-1, 1}).

        Args:
            f: challenge polynomial

        Returns:
            True if f is a valid challenge polynomial, False otherwise.
    """
    nonzeros = [c for c in f.list() if c != 0]

    return len(nonzeros) == 60 and all(c in (1, Q - 1) for c in nonzeros)
