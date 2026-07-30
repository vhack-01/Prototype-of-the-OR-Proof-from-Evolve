import statistics
import struct
from datetime import datetime
from math import sqrt

import sage.all as sg

from benchmark.benchmark import serialize_challenge_polynomial
from commitment.commitment import open, commit, generate_commitment_key
from or_proof.prover import generate_or_proof, generate_challenge_polynomial
from or_proof.verifier import verify_or_proof, is_valid_challenge_polynomial
from config.ring import Rq
from config.params import D, N, Q, B_R, B_OR_PRIME, SIGMA_OR, SIGMA_COMMITMENT, N_A
from simulate_or_proof import split_vote
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
#  The full test suite can be found at the bottom of this file.
# --------------------------------------------------------

# ------------------------------------------------
#  Unit Tests
# ------------------------------------------------

def test_norm_rq_vector():
    """
        Test that shared_utils.norm_rq_vector works correctly.
    """
    print("Testing shared_utils.norm_rq_vector...")

    # generate vector of polynomials
    coeff_lists = [[random.randint(-(Q - 1) // 2, Q // 2) for _ in range(N)] for _ in range(2 * D + 1)]
    polys = [Rq(coeff_list) for coeff_list in coeff_lists]
    vec = sg.vector(Rq, polys)

    # manually calculate expected norm
    expected_norm = sqrt(sum(coeff ** 2 for coeff_list in coeff_lists for coeff in coeff_list))

    assert norm_rq_vector(vec) == expected_norm, "Norm was not calculated correctly"


def test_generate_challenge_polynomial():
    """
        Test that prover.generate_challenge_polynomial works correctly.
    """
    print("Testing prover.generate_challenge_polynomial...")

    poly = generate_challenge_polynomial()
    nonzeros = [coeff for coeff in poly.list() if coeff != 0]

    assert len(nonzeros) == 60 and all(coeff in (1, Q - 1) for coeff in nonzeros), \
        "Generated challenge polynomial was not valid"


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

    assert is_valid_challenge_polynomial(poly), "Valid challenge polynomial was rejected"


def test_is_valid_challenge_polynomial_reject_invalid_entries():
    """
        Test that verifier.is_valid_challenge_polynomial rejects a challenge polynomial with invalid entries.
    """
    print("Testing verifier.is_valid_challenge_polynomial with invalid entries...")

    # Generate malformed challenge polynomial
    indices = random.sample(range(N), 60)
    coeffs = [0] * N
    for idx in indices:
        coeffs[idx] = random.choice([2, -2])  # invalid entries
    poly = Rq(coeffs)

    assert not is_valid_challenge_polynomial(poly), "Challenge polynomial with invalid entries was falsely accepted"


def test_is_valid_challenge_polynomial_reject_too_many_nonzeroes():
    """
        Test that verifier.is_valid_challenge_polynomial rejects a challenge polynomial with too many nonzeros.
    """
    print("Testing verifier.is_valid_challenge_polynomial with too many nonzeroes...")

    # Generate malformed challenge polynomial
    indices = random.sample(range(N), 61)  # one nonzero coefficient too much
    coeffs = [0] * N
    for idx in indices:
        coeffs[idx] = random.choice([-1, 1])
    poly = Rq(coeffs)

    assert not is_valid_challenge_polynomial(poly), "Challenge polynomial with too many nonzeroes was falsely accepted"


def test_is_valid_challenge_polynomial_reject_too_little_nonzeroes():
    """
        Test that verifier.is_valid_challenge_polynomial rejects a challenge polynomial with too little nonzeros.
    """
    print("Testing verifier.is_valid_challenge_polynomial with too little zeroes...")

    # Generate malformed challenge polynomial
    indices = random.sample(range(N), 59)  # one nonzero coefficient too little
    coeffs = [0] * N
    for idx in indices:
        coeffs[idx] = random.choice([-1, 1])
    poly = Rq(coeffs)

    assert not is_valid_challenge_polynomial(poly), \
        "Challenge polynomial with too little nonzeroes was falsely accepted"


def test_serialize_rq_vector():
    """
        Serialize a vector with one polynomial with shared_utils.serialize_rq_vector, verify bytes and deserialize it.
    """
    print("Testing that serialize_rq_vector works correctly...")

    # Create a polynomial with known coefficients
    poly = Rq([1, -2, 3, 0, -5] + [0] * (N - 5))  # length N
    result = serialize_rq_vector([poly])

    # Check length: N coefficients * 4 bytes each
    assert len(result) == N * 4

    # Unpack and compare
    unpacked = struct.unpack('<' + 'i' * N, result)
    expected = [int(c.lift_centered()) for c in poly.list()]

    assert unpacked == tuple(expected), "Serializing a vector did not work correctly"


def test_serialize_challenge_polynomial():
    """
        Serialize a challenge polynomial with benchmark.serialize_challenge_polynomial, verify bytes and deserialize it.
    """
    print("Testing that benchmark.serialize_challenge_polynomial works correctly...")

    # Generate a valid challenge polynomial
    poly = generate_challenge_polynomial()

    # Serialize it
    data = serialize_challenge_polynomial(poly)

    # Expected length: 60 indices * 2 bytes + 8 bytes for signs = 128 bytes
    assert len(data) == 128, f"Expected 128 bytes, got {len(data)}"

    # Reconstruct the polynomial from the serialized data
    indices = struct.unpack('<' + 'H' * 60, data[:120])
    signs = struct.unpack('<Q', data[120:128])[0]

    # Build coefficient list
    new_coeffs = [0] * N
    for bit, idx in enumerate(indices):
        new_coeffs[idx] = -1 if (signs >> bit) & 1 else 1

    recovered_poly = Rq(new_coeffs)

    # Verify that the reconstructed polynomial matches the original
    assert poly == recovered_poly, "Serializing a challenge polynomial did not work correctly"


def test_split_vote():
    """
        Test that simulate_or_proof.split_vote yields a valid result for both valid votes.
    """
    print("Testing simulate_or_proof.split_vote...")

    for m in (0, 1):
        shares = split_vote(m)

        assert len(shares) == N_A
        assert sum(shares) % Q == m


def test_sample_randomness_commitment():
    """
        Test that gaussian_sampler.sample_randomness_commitment yields a result
        with standard deviation roughly SIGMA_COMMITMENT.
    """
    print("Testing that the standard deviation of the values in the vector returned by "
          "gaussian_sampler.sample_randomness_commitment is roughly SIGMA_COMMITMENT...")

    # Sample vector
    vec = sample_randomness_commitment()

    # Get standard deviation of all coefficients
    coeffs = [int(coeff.lift_centered()) for poly in vec for coeff in poly]
    std = statistics.stdev(coeffs)

    assert abs(std - SIGMA_COMMITMENT) / SIGMA_COMMITMENT < 0.05, "Standard deviation was too far off"


def test_sample_randomness_or_proof():
    """
        Test that gaussian_sampler.sample_randomness_or_proof yields a result
        with standard deviation roughly SIGMA_OR.
    """
    print("Testing that the standard deviation of the values in the vector returned by "
          "gaussian_sampler.sample_randomness_or_proof is roughly SIGMA_OR...")

    # Sample vector
    vec = sample_randomness_or_proof()

    # Get standard deviation of all coefficients
    coeffs = [int(coeff.lift_centered()) for poly in vec for coeff in poly]
    std = statistics.stdev(coeffs)

    assert abs(std - SIGMA_OR) / SIGMA_OR < 0.05, "Standard deviation was too far off"


# ------------------------------------------------
#  Integration Tests
# ------------------------------------------------

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


def test_commitment_randomness_holds_bound():
    """
        Test that the randomness vectors sampled for commitments consistently have a small norm.
    """
    print("Testing that sample_randomness_commitment produces vectors with small norms...")

    for _ in range(100):
        assert norm_rq_vector(sample_randomness_commitment()) <= B_R, "Commitment randomness should have small norm"


def test_or_proof_randomness_holds_bound():
    """
        Test that the randomness vectors sampled for OR-proofs consistently have a small norm.
    """
    print("Testing that sample_randomness_or_proof produces vectors with small norms...")

    for _ in range(100):
        assert norm_rq_vector(sample_randomness_or_proof()) <= B_OR_PRIME, \
            "OR-proof randomness should have small norm"


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
#  Commitment Scheme
# ----------------------------------------

def test_commitment_scheme():
    """
        Test the full commitment flow (Keygen, Commit, Open).
    """
    print("Testing commitment scheme (Keygen, Commit, Open)...")

    m1 = 1
    C = generate_commitment_key()
    c, r = commit(C, m1)
    m2 = open(C, c, r)

    assert m1 == m2, "Opening of a valid commitment failed"


def test_reject_opening_big_randomness():
    """
        Test that opening a commitment with a big randomness is rejected.
    """
    print("Testing that opening a commitment with a big randomness is rejected...")

    #  Generate commitment key and commitment
    C = generate_commitment_key()
    r = sg.vector([Rq(poly) for poly in [(Q - 1) // 2 for _ in range(2 * D + 1)]])  # force big randomness
    c = C * r  # for m = 0

    assert open(C, c, r) is None, "Big randomness was not rejected"


def test_reject_opening_mismatched_key_and_commitment():
    """
        Test that opening a commitment with a mismatched key and commitment is rejected.
    """
    print("Testing that opening a commitment with a mismatched key and commitment is rejected...")

    # Create commitment and then a new commitment key
    c, r = commit(generate_commitment_key(), 0)
    C = generate_commitment_key()

    # C is not the one that c was created with
    assert open(C, c, r) is None, "Opening of mismatched commitment key and commitment succeeded but should not have"


def test_commitment_homomorphism():
    """
    Test that commitments are additively-homomorphic.
    """
    print("Testing commitment homomorphism...")

    # Create two commitments
    m1 = 1
    m2 = 2
    C = generate_commitment_key()
    c1, r1 = commit(C, m1)
    c2, r2 = commit(C, m2)

    # Sum the commitments and the openings
    c_sum = c1 + c2
    r_sum = r1 + r2

    # Open the sum
    m3 = open(C, c_sum, r_sum)

    assert m3 == m1 + m2, "Commitment scheme should be homomorphic"


# ----------------------------------------
#  OR-Proof
# ----------------------------------------

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

        Args:
            m: the invalid message (can not be 0 or 1)
    """
    print("Testing proof for an invalid message...")

    C = generate_commitment_key()
    c, r = commit(C, m)
    r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

    assert not verify_or_proof(C, c, r0, r1, f0, f1), f"Proof for m={m} should be invalid"


def test_tampered_commitment_key():
    """
    Tamper with the commitment key and verify that the proof is rejected.
    """
    print("Testing tampered commitment key...")

    C = generate_commitment_key()
    c, r = commit(C, 0)
    r0, r1, f0, f1, _ = generate_or_proof(0, C, c, r)

    # Modify the commitment key slightly (e.g. add 1 to the top left coefficient)
    C[0, 0] += 1

    assert not verify_or_proof(C, c, r0, r1, f0, f1), "Tampered commitment should be invalid"


def test_tampered_commitment():
    """
    Tamper with the commitment and verify that the proof is rejected.
    """
    print("Testing tampered commitment...")

    C = generate_commitment_key()
    c, r = commit(C, 0)
    r0, r1, f0, f1, _ = generate_or_proof(0, C, c, r)

    # Modify the commitment slightly (e.g. add 1 to the last coefficient)
    modified_c = list(c)
    modified_c[-1] += 1
    modified_c = sg.vector(Rq, modified_c)

    assert not verify_or_proof(C, modified_c, r0, r1, f0, f1), "Tampered commitment should be invalid"


def test_tampered_proof_r0():
    """
        Tamper with the r0 of a proof and verify that it is rejected.
    """
    print(f"Testing valid OR-proof where r0 has been tampered with...")

    # Generate valid proof
    m = 0
    C = generate_commitment_key()
    c, r = commit(C, m)
    r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

    # Modify r0 (e.g. add a random polynomial to the first entry)
    modified_r0 = list(r0)
    modified_r0[0] += Rq.random_element()
    modified_r0 = sg.vector(Rq, modified_r0)

    assert not verify_or_proof(C, c, modified_r0, r1, f0, f1), "Tampered proof should be invalid"


def test_tampered_proof_r1():
    """
        Tamper with the r1 of a proof and verify that it is rejected.
    """
    print(f"Testing valid OR-proof where r1 has been tampered with...")

    # Generate valid proof
    m = 0
    C = generate_commitment_key()
    c, r = commit(C, m)
    r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

    # Modify r1 (e.g. add a random polynomial to the first entry)
    modified_r1 = list(r1)
    modified_r1[0] += Rq.random_element()
    modified_r1 = sg.vector(Rq, modified_r1)

    assert not verify_or_proof(C, c, r0, modified_r1, f0, f1), "Tampered proof should be invalid"


def test_tampered_proof_f0():
    """
        Tamper with the f0 of a proof and verify that it is rejected.
    """
    print(f"Testing valid OR-proof where f0 has been tampered with...")

    # Generate valid proof
    m = 0
    C = generate_commitment_key()
    c, r = commit(C, m)
    r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

    # Modify f0 (e.g. change first entry to an invalid value)
    modified_f0 = f0.list()
    modified_f0[0] = 5
    modified_f0 = Rq(modified_f0)

    assert not verify_or_proof(C, c, r0, r1, modified_f0, f1), "Tampered proof should be invalid"


def test_tampered_proof_f1():
    """
        Tamper with the f1 of a proof and verify that it is rejected.
    """
    print(f"Testing valid OR-proof where f1 has been tampered with...")

    # Generate valid proof
    m = 0
    C = generate_commitment_key()
    c, r = commit(C, m)
    r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

    # Modify f1 (e.g. change first entry to an invalid value)
    modified_f1 = f1.list()
    modified_f1[0] = 5
    modified_f1 = Rq(modified_f1)

    assert not verify_or_proof(C, c, r0, r1, f0, modified_f1), "Tampered proof should be invalid"


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


def test_mismatch_invalid_commitment_invalid_proof():
    """
        Generate commitment and OR-proof with different invalid messages. Verifying should fail.
    """
    print("Testing that verification fails if commitment and proof were generated with "
          "different invalid messages...")

    C = generate_commitment_key()
    c, r = commit(C, 5)
    r0, r1, f0, f1, _ = generate_or_proof(-1, C, c, r)

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


def test_random_proofs(iterations=1000):
    """
        Test OR-proof generation and verification for a random m multiple times to ensure it works repeatedly.

        Args:
            iterations: number of OR-proofs to simulate
    """
    current_time_start = datetime.now().strftime("%H:%M:%S")
    print(f"Testing random OR-proofs started at {current_time_start} | Running {iterations} iterations")

    for i in range(iterations):
        m = random.randint(-5, 5)
        C = generate_commitment_key()
        c, r = commit(C, m)
        r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

        if m in (0, 1):
            assert verify_or_proof(C, c, r0, r1, f0, f1), f"Proof for m={m} should be accepted"
        else:
            assert not verify_or_proof(C, c, r0, r1, f0, f1), f"Proof for m={m} should be rejected"

    current_time_end = datetime.now().strftime("%H:%M:%S")
    print("Testing random OR-proofs finished at", current_time_end)


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

    # Main
    for _ in range(iterations):
        m = random.randint(0, 1)
        C = generate_commitment_key()
        c, r = commit(C, m)

        # Measure attempts
        _, _, _, _, attempts = generate_or_proof(m, C, c, r)
        attempts_counter += attempts

    avg_attempts = attempts_counter / iterations

    assert 2.85 < avg_attempts < 3.15, f"Average attempts should be ~3, got {avg_attempts:.2f}"

    # Output results
    print(f"    Average attempts needed to generate a proof: {avg_attempts:.2f}")

    current_time_end = datetime.now().strftime("%H:%M:%S")
    print("Testing Rejection Sampling finished at", current_time_end)


if __name__ == "__main__":
    print("----------- Unit Tests -----------")
    test_norm_rq_vector()
    test_generate_challenge_polynomial()
    test_is_valid_challenge_polynomial_accept()
    test_is_valid_challenge_polynomial_reject_invalid_entries()
    test_is_valid_challenge_polynomial_reject_too_many_nonzeroes()
    test_is_valid_challenge_polynomial_reject_too_little_nonzeroes()
    test_serialize_rq_vector()
    test_serialize_challenge_polynomial()
    test_split_vote()
    test_sample_randomness_commitment()
    test_sample_randomness_or_proof()

    print("\n----------- Integration Tests -----------")
    print("\n------ Helper/Utility functions ------")
    test_generating_and_validating_challenge_polynomial()
    test_commitment_randomness_holds_bound()
    test_or_proof_randomness_holds_bound()
    test_computing_fiat_shamir_challenge_deterministic()
    test_fiat_shamir_challenge_application()

    print("------ Commitment Scheme ------")
    test_commitment_scheme()
    test_reject_opening_big_randomness()
    test_reject_opening_mismatched_key_and_commitment()
    test_commitment_homomorphism()

    print("\n------ OR-proof ------")
    test_valid_proofs()
    test_invalid_proof(-1)
    test_invalid_proof(2)
    test_tampered_commitment_key()
    test_tampered_commitment()
    test_tampered_proof_r0()
    test_tampered_proof_r1()
    test_tampered_proof_f0()
    test_tampered_proof_f1()
    test_mismatch_invalid_commitment_valid_proof()
    test_mismatch_invalid_commitment_invalid_proof()
    test_mismatch_valid_commitment_invalid_proof()
    test_mismatch_valid_commitment_valid_proof()

    ## these may run a long time depending on the chosen iterations
    ## with iterations=1000 each takes about 3 min
    test_random_proofs(1000)
    test_rejection_sampling(1000)

    print("All tests passed!")
