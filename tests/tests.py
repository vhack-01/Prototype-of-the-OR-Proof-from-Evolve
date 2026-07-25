import statistics
import struct
from datetime import datetime
from math import sqrt

import sage.all as sg

from commitment.commitment import open, commit, generate_commitment_key
from or_proof.prover import generate_or_proof, generate_challenge_polynomial
from or_proof.verifier import verify_or_proof, is_valid_challenge_polynomial
from config.ring import Rq
from config.params import D, N, Q, B_R, B_OR_PRIME, SIGMA_OR, SIGMA_COMMITMENT
from simulate_or_proof import simulate_or_proof
from utils.fiat_shamir import hash_to_challenge, apply_challenge
from utils.gaussian_sampler import sample_randomness_commitment, sample_randomness_or_proof
from utils.shared_utils import norm_rq_vector, serialize_rq_vector

# Set deterministic seed so tests are reproducible
SEED = 42
import random

random.seed(SEED)

from sage.misc.randstate import set_random_seed

set_random_seed(SEED)


# --------------------------------------------------------
#  Functions for Running Tests
# --------------------------------------------------------

# ------------------------------------------------
#  Unit Tests
# ------------------------------------------------

def test_norm_rq_vector():
    """
        Test that shared_utils.norm_rq_vector works correctly.
    """
    print("Testing shared_utils.norm_rq_vector...")

    coeff_lists = [[random.randint(-(Q - 1) // 2, Q // 2) for _ in range(N)] for _ in range(2 * D + 1)]
    sum_coeffs = sum(coeff ** 2 for coeff_list in coeff_lists for coeff in coeff_list)

    polys = [Rq(coeff_list) for coeff_list in coeff_lists]

    vec = sg.vector(Rq, polys)

    assert norm_rq_vector(vec) == sqrt(sum_coeffs)


def test_generate_challenge_polynomial():
    """
        Test that prover.generate_challenge_polynomial works correctly.
    """
    print("Testing prover.generate_challenge_polynomial...")

    poly = generate_challenge_polynomial()
    nonzeros = [coeff for coeff in poly.list() if coeff != 0]

    assert len(nonzeros) == 60 and all(coeff in (1, Q - 1) for coeff in nonzeros)


def test_is_valid_challenge_polynomial_accept():
    """
        Test that verifier.is_valid_challenge_polynomial accepts valid challenge polynomials.
    """
    print("Testing verifier.is_valid_challenge_polynomial...")

    # Generate wellformed challenge polynomial
    indices = random.sample(range(N), 60)
    coeffs = [0] * N
    for idx in indices:
        coeffs[idx] = random.choice([1, -1])
    poly = Rq(coeffs)

    assert is_valid_challenge_polynomial(poly)


def test_is_valid_challenge_polynomial_reject():
    """
        Test that verifier.is_valid_challenge_polynomial rejects malformed challenge polynomials.
    """
    print("Testing verifier.is_valid_challenge_polynomial...")

    # Generate malformed challenge polynomial
    indices = random.sample(range(N), 60)
    coeffs = [0] * N
    for idx in indices:
        coeffs[idx] = random.choice([2, -2])
    poly = Rq(coeffs)

    assert not is_valid_challenge_polynomial(poly)


def test_serialize_rq_vector_one_poly():
    """
        Serialize a vector with one polynomial and verify bytes.
    """
    print("Testing that serialize_rq_vector works correctly with one polynomial...")

    # Create a polynomial with known coefficients
    poly = Rq([1, -2, 3, 0, -5] + [0] * (N - 5))  # length N

    result = serialize_rq_vector([poly])

    # Check length: N coefficients * 4 bytes each
    assert len(result) == N * 4

    # Unpack and compare
    unpacked = struct.unpack('<' + 'i' * N, result)
    expected = [int(c.lift_centered()) for c in poly.list()]
    assert unpacked == tuple(expected)


def test_serialize_rq_vector_empty():
    """
        Test that serializing and empty vector gives empty bytes.
    """
    print("Testing that serialize_rq_vector works correctly with an empty vector...")

    vec = []
    result = serialize_rq_vector(vec)
    assert result == b''


def test_sample_randomness_commitment():
    print("Testing that the standard deviation of the values in the vector returned by "
          "gaussian_sampler.sample_randomness_commitment is roughly SIGMA_COMMITMENT...")

    vec = sample_randomness_commitment()
    coeffs = [int(coeff.lift_centered()) for poly in vec for coeff in poly]

    std = statistics.stdev(coeffs)

    assert abs(std - SIGMA_COMMITMENT) / SIGMA_COMMITMENT < 0.05


def test_sample_randomness_or_proof():
    print("Testing that the standard deviation of the values in the vector returned by "
          "gaussian_sampler.sample_randomness_or_proof is roughly SIGMA_OR...")

    vec = sample_randomness_or_proof()
    coeffs = [int(coeff.lift_centered()) for poly in vec for coeff in poly]

    std = statistics.stdev(coeffs)

    assert abs(std - SIGMA_OR) / SIGMA_OR < 0.05


# ------------------------------------------------
#  Integration Tests
# ------------------------------------------------

# ----------------------------------------
#  Commitment Scheme
# ----------------------------------------

def test_commitment_scheme():
    """
        Test the full commitment flow (Keygen, Commit, Open).
    """
    print("Testing commitment scheme...")

    m1 = 2
    C = generate_commitment_key()
    c, r = commit(C, m1)
    m2 = open(C, c, r)

    assert m1 == m2, "Opening of a valid commitment failed"


def test_commitment_homomorphism():
    """
    Test that commitments are additively homomorphic.
    """
    print("Testing commitment homomorphism...")
    m1 = 0
    m2 = 0
    C = generate_commitment_key()
    c1, r1 = commit(C, m1)
    c2, r2 = commit(C, m2)

    # Sum the commitments and the openings
    c_sum = c1 + c2
    r_sum = r1 + r2

    m3 = open(C, c_sum, r_sum)

    assert m3 == m1 + m2, "Commitment scheme should be homomorphic"


def test_commitment_randomness_holds_bound():
    """
        Test that the randomness vectors sampled for commitments consistently have a small norm.
    """
    print("Testing that sample_randomness_commitment produces vectors with small norms...")

    for _ in range(100):
        assert norm_rq_vector(sample_randomness_commitment()) <= B_R, "Commitment randomness should have small norm"


def test_reject_opening_big_randomness():
    """
        Test that opening a commitment with a big randomness is rejected.
    """
    print("Testing that opening a commitment with a big randomness is rejected...")

    C = generate_commitment_key()
    c, r = commit(C, 0)

    # force randomness to be too large
    while norm_rq_vector(r) <= B_R:
        c *= 1000
        r *= 1000

    assert open(C, c, r) is None


def test_mismatched_key_and_commitment():
    """
        Test that opening a commitment with a mismatched key and commitment is rejected.
    """
    print("Testing that opening a commitment with a mismatched key and commitment is rejected...")

    c, r = commit(generate_commitment_key(), 0)
    C = generate_commitment_key()

    # C is not the one that c was created with
    assert open(C, c, r) is None


# ----------------------------------------
#  OR-Proof
# ----------------------------------------

def test_tampered_proof():
    """
        Tamper with a proof and verify that it is rejected.
    """
    print(f"Testing valid OR-proof that has been tampered with...")

    m = 0
    C = generate_commitment_key()
    c, r = commit(C, m)
    r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

    # Modify r0 (e.g., add a random polynomial to the first entry)
    modified_r0 = list(r0)
    modified_r0[0] += Rq.random_element()
    modified_r0 = sg.vector(Rq, modified_r0)

    assert not verify_or_proof(C, c, modified_r0, r1, f0, f1), "Tampered proof should be invalid"


def test_valid_proofs():
    """
        Test OR-proof generation and verification for m = 0 and m = 1.
    """
    print("Testing valid OR-proofs...")

    for m in (0, 1):
        # Generate proof
        C = generate_commitment_key()
        c, r = commit(C, m)
        r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

        # Verify proof
        assert verify_or_proof(C, c, r0, r1, f0, f1), f"Proof for m={m} should be valid"

        print(f"  m = {m}: OK")


def test_invalid_proof(m):
    """
        Create a commitment to a message not in {0,1} and try to prove it; should fail.
    """
    print("Testing proof for an invalid message...")

    C = generate_commitment_key()
    c, r = commit(C, m)
    r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

    assert not verify_or_proof(C, c, r0, r1, f0, f1), f"Proof for m={m} should be invalid"


def test_or_proof_randomness_holds_bound():
    """
        Test that the randomness vectors sampled for OR-proofs consistently have a small norm.
    """
    print("Testing that sample_randomness_or_proof produces vectors with small norms...")

    for _ in range(100):
        assert norm_rq_vector(sample_randomness_or_proof()) <= B_OR_PRIME, \
            "OR-proof randomness should have small norm"


# ----------------------------------------
#  Helper Functions
# ----------------------------------------


def test_generating_and_validating_challenge_polynomial():
    """
        Test the functions "prover.generate_challenge_polynomial" and "verifier.is_valid_challenge_polynomial" together
    """
    print("Test generating and validating challenge polynomials...")

    assert is_valid_challenge_polynomial(generate_challenge_polynomial()), \
        "Challenge polynomial should be generated and validated correctly"


def test_reject_challenge_polynomial_with_too_many_zeroes():
    """
        Test that a challenge polynomial with too many zeroes is rejected.
    """
    print("Test that a challenge polynomial with too many zeroes is rejected...")
    coeffs = generate_challenge_polynomial().list()

    # tamper with the polynomial
    for i in range(N):
        if coeffs[i] in (-1, 1):
            coeffs[i] = 0
            break

    assert not is_valid_challenge_polynomial(Rq(coeffs)), "Malformed challenge polynomial should be rejected"


def test_reject_challenge_polynomial_with_invalid_entries():
    """
        Test that a challenge polynomial with invalid entries is rejected.
    """
    print("Test that a challenge polynomial with invalid entries is rejected...")
    coeffs = generate_challenge_polynomial().list()

    # tamper with the polynomial
    for i in range(N):
        if coeffs[i] in (-1, 1):
            coeffs[i] = 2
            break

    assert not is_valid_challenge_polynomial(Rq(coeffs)), "Malformed challenge polynomial should be rejected"


def test_computing_fiat_shamir_challenge_deterministic():
    """
        Test that two challenges are equal if the same inputs were used.
    """

    print("Testing that computing the fiat shamir challenge is deterministic...")

    # Set up everything required to generate a challenge
    C = generate_commitment_key()
    m = 0
    c, r = commit(C, m)
    r_fake = sample_randomness_or_proof()
    f_fake = generate_challenge_polynomial()
    t_fake = C * r_fake + f_fake * sg.vector(Rq, [0] * D + [1 - m]) - f_fake * c
    rho = sample_randomness_or_proof()
    t_honest = C * rho

    # Generate two challenges with the same inputs
    perm1, signs1 = hash_to_challenge(c, t_honest, t_fake)
    perm2, signs2 = hash_to_challenge(c, t_honest, t_fake)

    # Check that they are the same
    assert perm1 == perm2 and signs1 == signs2


def test_fiat_shamir_challenge_application():
    """
        Test that applying a challenge and then applying its inverse yields the original polynomial.
    """
    print("Testing that applying and challenge and then its inverse yields the original polynomial...")

    # Set up everything required for the challenge
    C = generate_commitment_key()
    m = 0
    c, r = commit(C, m)
    r_fake = sample_randomness_or_proof()
    f_fake = generate_challenge_polynomial()
    t_fake = C * r_fake + f_fake * sg.vector(Rq, [0] * D + [1 - m]) - f_fake * c
    rho = sample_randomness_or_proof()
    t_honest = C * rho

    # Set up challenge and a polynomial
    perm, signs = hash_to_challenge(c, t_honest, t_fake)
    original_poly = generate_challenge_polynomial()

    # Apply the challenge and then its inverse
    poly1 = apply_challenge(original_poly, perm, signs, True)
    poly2 = apply_challenge(poly1, perm, signs, False)

    assert original_poly == poly2


# ----------------------------------------
#  System
# ----------------------------------------

def test_tampered_commitment():
    """
    Tamper with the commitment and verify that the proof is rejected.
    """
    print("Testing tampered commitment...")

    C = generate_commitment_key()
    c, r = commit(C, 0)
    r0, r1, f0, f1, _ = generate_or_proof(0, C, c, r)

    # Modify the commitment slightly (e.g., add 1 to the last coefficient)
    modified_c = list(c)
    modified_c[-1] += 1
    modified_c = sg.vector(Rq, modified_c)

    assert not verify_or_proof(C, modified_c, r0, r1, f0, f1), "Tampered commitment should be invalid"


def test_mismatch_invalid_commitment_valid_proof():
    """
        Generate commitment with an invalid and the proof with a valid message. Verifying should fail.
    """
    print("Testing that verification fails if commitment was generated with an invalid and "
          "the proof with a valid message...")

    C = generate_commitment_key()
    c, r = commit(C, 5)
    r0, r1, f0, f1, _ = generate_or_proof(0, C, c, r)

    assert not verify_or_proof(C, c, r0, r1, f0, f1), "Proof verification should fail"


def test_mismatch_valid_commitment_invalid_proof():
    """
        Generate commitment with a valid and the proof with an invalid message. Verifying should fail.
    """
    print("Testing that verification fails if commitment was generated with a valid and "
          "the proof with an invalid message...")

    C = generate_commitment_key()
    c, r = commit(C, 0)
    r0, r1, f0, f1, _ = generate_or_proof(3, C, c, r)

    assert not verify_or_proof(C, c, r0, r1, f0, f1), "Proof verification should fail"


def test_mismatch_valid_commitment_valid_proof():
    """
        Generate commitment and OR-proof with valid, but different messages. Verifying should fail.
    """
    print("Testing that verification fails if commitment and proof were generated with "
          "valid, but different messages...")

    C = generate_commitment_key()
    c, r = commit(C, 0)
    r0, r1, f0, f1, _ = generate_or_proof(1, C, c, r)

    assert not verify_or_proof(C, c, r0, r1, f0, f1), "Proof verification should fail"


def test_reject_proof_with_invalid_challenge_polynomial():
    """
        Testing that a proof where f0 has been swapped for an invalid polynomial gets rejected.
    """
    print("Testing that proof with invalid challenge polynomial gets rejected...")

    # Generate proof
    m = 1
    C = generate_commitment_key()
    c, r = commit(C, m)
    r0, r1, _, f1, _ = generate_or_proof(m, C, c, r)

    # Generate invalid polynomial
    coeffs = generate_challenge_polynomial().list()
    coeffs[0] = 2
    f0 = Rq(coeffs)

    assert not verify_or_proof(C, c, r0, r1, f0, f1), "Proof verification should fail if f0 is malformed"


def test_random_valid_proofs(iterations=1000):
    """
        Test OR-proof generation and verification for a random m in {0,1} multiple times to ensure it works repeatedly.

        Args:
            iterations: number of OR-proofs to simulate
    """
    current_time_start = datetime.now().strftime("%H:%M:%S")
    print(f"Testing random valid OR-proofs started at {current_time_start} | Running {iterations} iterations")

    for i in range(iterations):
        m = random.randint(0, 1)
        C = generate_commitment_key()
        c, r = commit(C, m)
        r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

        assert verify_or_proof(C, c, r0, r1, f0, f1), f"Proof for m={m} should be valid"

    current_time_end = datetime.now().strftime("%H:%M:%S")
    print("Testing random valid OR-proofs finished at", current_time_end)


def test_rejection_sampling(iterations=1000):
    """
        According to the paper, it should take on average 3 tries to generate an OR-proof.
        To test this, generate 'iterations' OR-proofs and calculate the mean.

        Args:
            iterations: number of OR-proofs to simulate
    """
    current_time_start = datetime.now().strftime("%H:%M:%S")
    print(f"Testing Rejection Sampling started at {current_time_start} | Running {iterations} iterations")

    attempts_counter = 0

    # Warm-up
    for _ in range(3):
        simulate_or_proof(0)

    # Main
    for _ in range(iterations):
        m = random.randint(0, 1)
        C = generate_commitment_key()
        c, r = commit(C, m)

        # Measure attempts
        _, _, _, _, attempts = generate_or_proof(m, C, c, r)
        attempts_counter += attempts

    avg_attempts = attempts_counter / iterations

    assert 2.5 < avg_attempts < 3.5, f"Average attempts should be ~3, got {avg_attempts:.2f}"

    # Output results
    print(f"    Average attempts needed to generate a proof: {avg_attempts:.2f}")

    current_time_end = datetime.now().strftime("%H:%M:%S")
    print("Testing Rejection Sampling finished at", current_time_end)


if __name__ == "__main__":
    print("----------- Unit Tests -----------")
    test_norm_rq_vector()
    test_generate_challenge_polynomial()
    test_is_valid_challenge_polynomial_accept()
    test_is_valid_challenge_polynomial_reject()
    test_serialize_rq_vector_one_poly()
    test_serialize_rq_vector_empty()
    test_sample_randomness_commitment()
    test_sample_randomness_or_proof()

    print("\n----------- Integration Tests -----------")
    print("------ Commitment Scheme ------")
    test_commitment_scheme()
    test_commitment_homomorphism()
    test_commitment_randomness_holds_bound()
    test_reject_opening_big_randomness()
    test_mismatched_key_and_commitment()

    print("\n------ OR-Proof ------")
    test_tampered_proof()
    test_valid_proofs()
    test_invalid_proof(-1)
    test_invalid_proof(3)
    test_invalid_proof(346334343)
    test_or_proof_randomness_holds_bound()

    print("\n------ Helper functions ------")
    test_generating_and_validating_challenge_polynomial()
    test_reject_challenge_polynomial_with_too_many_zeroes()
    test_reject_challenge_polynomial_with_invalid_entries()
    test_computing_fiat_shamir_challenge_deterministic()
    test_fiat_shamir_challenge_application()

    print("\n------ System ------")
    test_tampered_commitment()
    test_mismatch_invalid_commitment_valid_proof()
    test_mismatch_valid_commitment_invalid_proof()
    test_mismatch_valid_commitment_valid_proof()
    test_reject_proof_with_invalid_challenge_polynomial()

    ## these may run a long time depending on the chosen amount of iterations
    test_random_valid_proofs(1000)
    test_rejection_sampling(1000)

    print("All tests passed!")
