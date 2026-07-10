from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
import sage.all as sg

from config.params import N, D, SIGMA_OR, SIGMA_COMMITMENT
from config.ring import Rq

commitment_sampler = DiscreteGaussianDistributionIntegerSampler(SIGMA_COMMITMENT)
proof_sampler = DiscreteGaussianDistributionIntegerSampler(SIGMA_OR)

dim = N * (2 * D + 1)


# --------------------------------------------------------
#  Discrete Gaussian Sampling
# --------------------------------------------------------

def sample_randomness_for_commitment():
    """
        Sample a randomness vector for the OR proof. The coefficients of each polynomial
        are drawn from a discrete Gaussian distribution with standard deviation SIGMA_COMMITMENT. It uses
        Sage's DiscreteGaussianDistributionIntegerSampler, this is acceptable for prototyping, but not for
        production because it is susceptible to side-channel attacks.

        Returns:
            vector over Rq
    """
    return sample_randomness(commitment_sampler)


def sample_randomness_for_or_proof():
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
        Sample a vector of length N(2D+1) whose components are polynomials in Rq using the provided sampler.

        Args:
            sampler: the sampler to use

        Returns:
            vector over Rq
    """
    coeffs_list = sg.vector(sg.ZZ, [sampler() for _ in range(dim)]).list()

    chunks = [coeffs_list[i:i + N] for i in range(0, len(coeffs_list), N)]
    r_polys = [Rq(chunk) for chunk in chunks]

    return sg.vector(Rq, r_polys)
