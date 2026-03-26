import sage.all as sg

from config.ring import Rq
from config.params import D, SIGMA_COMMITMENT
from utils.shared_utils import sample_randomness


# --------------------------------------------------------
#  Commitment Scheme (EVOLVE paper section 3.1)
# --------------------------------------------------------

def generate_commitment(m):
    """
        Generate the commitment to a message m.

        Args:
            m: the message

        Returns:
            public commitment key
            commitment vector
            randomness vector
    """

    C = generate_commitment_key()
    c, r = commit(C, m)
    return C, c, r


def generate_commitment_key():  # Keygen
    """
        Generate the public commitment key C, a (d+1)x(2d+1) matrix over Rq.

        Returns:
            the public commitment key
    """
    A_prime = sg.matrix(Rq, D, D + 1, lambda i, j: Rq.random_element())
    I_d = sg.identity_matrix(Rq, D)
    A = A_prime.augment(I_d)
    B = sg.matrix(Rq, 1, 2 * D + 1, lambda i, j: Rq.random_element())
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
    r = sample_randomness(SIGMA_COMMITMENT)
    v: sg.vector = sg.vector(Rq, [0] * D + [m])
    c = C * r + v
    return c, r
