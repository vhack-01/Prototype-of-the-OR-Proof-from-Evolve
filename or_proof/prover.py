import random
from math import exp

import sage.all as sg

from config.params import N, D, SIGMA_OR
from config.ring import Rq
from utils.shared_utils import apply_permutation, center_coefficient
from utils.gaussian_sampler import sample_randomness_for_or_proof
from utils.fiat_shamir import hash_to_challenge


# --------------------------------------------------------
#  OR-Proof - Prover (EVOLVE paper section 3.2, Π_{OR} algorithm)
# --------------------------------------------------------

def generate_or_proof(m, C, c, r):
    """
        Generate an OR-proof for the statement "c is a commitment to m ∈ {0,1}".

        Args:
            m: message
            C: public commitment key
            c: commitment vector
            r: randomness vector used to create c

        Returns:
            two response vectors (r0, r1)
            two challenge polynomials (f0, f1)
            amounts of attempts needed to create the proof
    """
    attempts = 0
    while True:
        attempts += 1

        # (1) Sample fake randomness
        r_fake = sample_randomness_for_or_proof()  # r_{1-m}

        # (2) Generate fake challenge polynomial
        f_fake = generate_challenge_polynomial()  # f_{1-m}

        # (3) Compute fake commitment
        t_fake = compute_fake_commitment(m, C, c, r_fake, f_fake)  # t_{1-m}

        # (4) Sample honest randomness
        rho = sample_randomness_for_or_proof()

        # (5) Compute honest commitment
        t_honest = C * rho  # t_{m}

        # (6) Obtain challenge permutation
        if m == 0:
            t0 = t_honest
            t1 = t_fake
        else:
            t0 = t_fake
            t1 = t_honest

        perm, signs = hash_to_challenge(c, t0, t1)

        # (7) Compute honest challenge polynomial (f_{m})
        f_honest = apply_permutation(f_fake, perm, signs, ((2 * m - 1) == -1))

        # (8) Compute honest response
        r_honest = rho + f_honest * r  # r_{m}

        # (9) Perform rejection sampling
        if rejection_sample_keep(r_honest, f_honest, r):
            break

        # print("Aborted (Rejection sampling)")

    # (10) Output the proof
    if m == 0:
        r0, r1 = r_honest, r_fake
        f0, f1 = f_honest, f_fake
    else:
        r0, r1 = r_fake, r_honest
        f0, f1 = f_fake, f_honest

    return r0, r1, f0, f1, attempts


# --------------------------------------------------------
#  Helper Functions for the Prover
# --------------------------------------------------------

def compute_fake_commitment(m, C, c, r_fake, f_fake):
    """
        Generate a fake commitment for the OR-proof.

        Args:
            m: message
            C: public commitment key
            c: commitment vector
            r_fake: fake randomness
            f_fake: fake challenge

        Returns:
            the fake commitment
    """
    C_r = C * r_fake
    v = sg.vector(Rq, [0] * D + [1 - m])
    f_v = f_fake * v
    f_c = f_fake * c

    return C_r + f_v - f_c


def generate_challenge_polynomial():
    """
        Pick a random challenge polynomial from the challenge space.
        The polynomial must have exactly 60 non-zero coefficients, each being in {-1, 1} (see EVOLVE paper section 3.2).

        Returns:
            the challenge polynomial
    """
    indices = random.sample(range(N), 60)  # choose 60 random indices that will have non-zero coefficients
    coeffs = [0] * N
    for idx in indices:
        coeffs[idx] = random.choice([1, -1])
    return Rq(coeffs)


def rejection_sample_keep(r_m, f_m, r):
    """
    Implements the rejection sampling step, following the Theorem 2.5 in the EVOLVE paper.
    Returns True if the sample should be kept, False if it should be aborted.

    Args:
        r_m: the computed response vector
        f_m: the real challenge polynomial
        r: the real randomness used in the commitment

    Returns:
        True if the sample should be kept, False if it should be rejected.
    """
    # Compute shift
    v = f_m * r

    # Convert to integer coefficient vectors (centered, see EVOLVE paper section 2.1)
    r_m_ints = [center_coefficient(c) for poly in r_m for c in poly.list()]
    v_ints = [center_coefficient(c) for poly in v for c in poly.list()]

    # Compute squared Euclidean norm and dot product
    v_norm2 = sum(i ** 2 for i in v_ints)
    dot = sum(r_m_ints[i] * v_ints[i] for i in range(len(r_m_ints)))

    # Compute exponent = (||v||^2 - 2<r_m,v>) / (2σ^2)
    exponent = (v_norm2 - 2 * dot) / (2.0 * (SIGMA_OR ** 2))

    # Π_{OR} algorithm says to "Abort with probability 1 - min(..)", i.e. keep with probability min(..)
    return random.random() < min(exp(exponent) / 3.0, 1)
