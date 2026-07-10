from math import ceil, sqrt

# --------------------------------------------------------
#  Global parameters (as given in the EVOLVE paper)
# --------------------------------------------------------

# Parameters from Table 2 of the EVOLVE paper
N = 256                             # Ring dimension
Q = 2 ** 31 - 2 ** 7 - 2 ** 5 + 1   # Modulus
D = 7                               # Module size
SIGMA_COMMITMENT = 1                # Commitment standard deviation
N_A = 4                             # Number of authorities


def compute_parameters():
    """
        Compute the parameters sigma_OR and B_OR_prime according to the bounds
        given in the paper.

        Returns:
            sigma_OR, B_OR_prime, B_r
    """
    # all the bounds are given as >=, so we can use ceil() to mitigate potential floating-point errors
    B_OR = ceil(2 * N_A * sqrt(N * (2 * D + 1)) * SIGMA_COMMITMENT)     # chapter 5, B_{OR} >= ...
    sigma_OR = ceil(22 * sqrt(60) * B_OR)                               # Theorem 3.2., σ_{OR} >= ...
    B_OR_prime = ceil(2 * sqrt(N * (2 * D + 1)) * sigma_OR)             # Theorem 3.2. (or chapter 5), B'_{OR} >= ...
    B_r = ceil(2 * B_OR_prime)                                          # chapter 5, 2 * B'_{OR} <= B_r

    return sigma_OR, B_OR_prime, B_r


# Proof standard deviation, Bound for randomness of OR-proof, Bound for+ randomness of a commitment
SIGMA_OR, B_OR_PRIME, B_R = compute_parameters()
