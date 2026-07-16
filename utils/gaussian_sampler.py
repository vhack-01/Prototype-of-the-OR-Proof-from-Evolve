from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
import sage.all as sg

from config.params import N, D, SIGMA_OR, SIGMA_COMMITMENT
from config.ring import Rq

# --------------------------------------------------------
#  Discrete Gaussian Sampling
# --------------------------------------------------------

# create one sampler for each standard deviation
commitment_sampler = DiscreteGaussianDistributionIntegerSampler(SIGMA_COMMITMENT)
proof_sampler = DiscreteGaussianDistributionIntegerSampler(SIGMA_OR)

# length of each randomness vector
DIM = N * (2 * D + 1)


def sample_randomness_commitment():
    """
        Sample a randomness vector for the OR proof. The coefficients of each polynomial
        are drawn from a discrete Gaussian distribution with standard deviation SIGMA_COMMITMENT. It uses
        Sage's DiscreteGaussianDistributionIntegerSampler, this is acceptable for prototyping, but not for
        production because it is susceptible to side-channel attacks.

        Returns:
            vector over Rq
    """
    return sample_randomness(commitment_sampler)


def sample_randomness_or_proof():
    """
        Sample a randomness vector for the OR proof. The coefficients of each polynomial
        are drawn from a discrete Gaussian distribution with standard deviation SIGMA_OR. It uses
        Sage's DiscreteGaussianDistributionIntegerSampler, this is acceptable for prototyping, but not for
        production because it is susceptible to side-channel attacks.

        Returns:
            vector over Rq
    """
    return sample_randomness(proof_sampler)


def sample_randomness(sampler):
    """
        Sample a randomness vector of length DIM using the provided sampler, then reshape it into a vector of
        polynomials over Rq. The sampler must be an instance of DiscreteGaussianDistributionIntegerSampler.

        Args:
            sampler: the sampler to use

        Returns:
            vector over Rq
    """
    coeffs_list = sg.vector(sg.ZZ, [sampler() for _ in range(DIM)]).list()

    chunks = [coeffs_list[i:i + N] for i in range(0, len(coeffs_list), N)]
    r_polys = [Rq(chunk) for chunk in chunks]

    return sg.vector(Rq, r_polys)
