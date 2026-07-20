import sage.all as sg

from config.ring import Rq
from config.params import D, B_R
from utils.shared_utils import norm_rq_vector
from utils.gaussian_sampler import sample_randomness_commitment


# --------------------------------------------------------
#  Commitment Scheme (EVOLVE paper section 3.1)
# --------------------------------------------------------


def generate_commitment_key():  # Keygen
    """
        Generate the public commitment key C, a (d+1)x(2d+1) matrix over Rq.

        Returns:
            the public commitment key
    """
    # (1) Generate random module matrix
    A_prime = sg.random_matrix(Rq, D, D + 1)

    # (2) Construct matrix A by appending an identity matrix to A_prime
    I_d = sg.identity_matrix(Rq, D)
    A = A_prime.augment(I_d)

    # (3) Generate random row vector
    B = sg.random_matrix(Rq, 1, 2 * D + 1)

    # (4) Create final commitment key
    C = A.stack(B)

    return C


def commit(C, m):  # Commit
    """
        Commit to a message.

        Args:
            C: the public commitment key
            m: the message

        Returns:
            the commitment vector (length D+1)
            the randomness vector (length 2D+1)
    """
    # (1) Sample short randomness
    r = sample_randomness_commitment()

    # (2) Compute commitment
    v: sg.vector = sg.vector(Rq, [0] * D + [m])
    c = C * r + v

    return c, r


def open(C, c, r):  # Open
    """
        Open a commitment.

        Args:
            C: public commitment key
            c: commitment vector (length D+1)
            r: randomness vector (length 2D+1)

        Returns:
            message m if opening is valid, else None (⊥)
    """
    # (1)
    # (a) Compute c - C * r and check that the first D rows are zero polynomials
    diff = c - C * r
    for i in range(D):
        if not diff[i].is_zero():
            # (3) If a polynomial is nonzero, return None
            return None

    # (b) Check norm bound
    norm_r = norm_rq_vector(r)
    if norm_r > B_R:
        # (3) If the norm is too big, return None
        return None

    # (2) Extract the message from the last row and return it
    m_actual = diff[D][0].lift_centered()

    return m_actual
