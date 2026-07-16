from sage.stats.distributions.discrete_gaussian_polynomial import DiscreteGaussianDistributionPolynomialSampler
import sage.all as sg

from config.params import N, D, SIGMA_OR, SIGMA_COMMITMENT
from config.ring import Rq

# --------------------------------------------------------
#  Discrete Gaussian Sampling
#
#  IMPORTANT: This implementation uses SageMath's DiscreteGaussianDistributionPolynomialSampler.
#  This is acceptable for prototyping, but not for production because it is not constant-time.
# --------------------------------------------------------

# Polynomial ring over ZZ for sampling (coeffs are integers)
P = sg.ZZ['x']

# Create one sampler for each standard deviation
commitment_sampler = DiscreteGaussianDistributionPolynomialSampler(P, N, SIGMA_COMMITMENT)
proof_sampler = DiscreteGaussianDistributionPolynomialSampler(P, N, SIGMA_OR)

# Number of polynomials in a randomness vector
NUM_POLYS = 2 * D + 1


def sample_randomness(sampler):
    """
    Sample a randomness vector consisting of NUM_POLYS polynomials.
    Each polynomial is sampled independently using the provided polynomial sampler.

    Args:
        sampler: DiscreteGaussianDistributionPolynomialSampler instance

    Returns:
        vector over Rq (length NUM_POLYS)
    """
    # Generate all polynomials
    r_polys = [sampler() for _ in range(NUM_POLYS)]

    # Convert each to Rq
    r_polys_rq = [Rq(poly) for poly in r_polys]

    return sg.vector(Rq, r_polys_rq)


def sample_randomness_commitment():
    """
    Sample randomness for the commitment phase.

    Returns:
        vector over Rq
    """
    return sample_randomness(commitment_sampler)


def sample_randomness_or_proof():
    """
    Sample randomness for the OR proof.

    Returns:
        vector over Rq
    """
    return sample_randomness(proof_sampler)
