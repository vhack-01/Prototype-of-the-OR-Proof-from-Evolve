from datetime import datetime
from math import sqrt

import sage.all as sg

from commitment.commitment import open, commit, generate_commitment_key
from or_proof.prover import generate_or_proof, generate_challenge_polynomial
from or_proof.verifier import verify_or_proof, is_valid_challenge_polynomial
from config.ring import Rq
from config.params import D, N, Q, B_R, B_OR_PRIME
from simulate_or_proof import simulate_or_proof
from utils.gaussian_sampler import sample_randomness_commitment, sample_randomness_or_proof
from utils.shared_utils import norm_rq_vector

# Set deterministic seed so tests are reproducible
SEED = 42
import random

random.seed(SEED)

from sage.misc.randstate import set_random_seed

set_random_seed(SEED)


# --------------------------------------------------------
#  Functions for Running Tests
# --------------------------------------------------------

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


def test_invalid_proof(m):
    """
        Create a commitment to a message not in {0,1} and try to prove it; should fail.
    """
    print("Testing proof for an invalid message...")

    C = generate_commitment_key()
    c, r = commit(C, m)
    r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

    assert not verify_or_proof(C, c, r0, r1, f0, f1), f"Proof for m={m} should be invalid"


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


def test_generating_and_validating_challenge_polynomial():
    """
        Test the functions "prover.generate_challenge_polynomial" and "verifier.is_valid_challenge_polynomial" together
    """
    print("Test generating and validating challenge polynomials...")
    poly = generate_challenge_polynomial()

    assert is_valid_challenge_polynomial(poly), "Challenge polynomial should be generated and validated correctly"


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


def test_norm_rq_vector():
    """
        Test that shared_utils.norm_rq_vector works correctly.
    """
    print("Testing norm_rq_vector...")

    coeff_lists = [[random.randint(-(Q - 1) // 2, Q // 2) for _ in range(N)] for _ in range(2 * D + 1)]
    sum_coeffs = sum(coeff ** 2 for coeff_list in coeff_lists for coeff in coeff_list)

    polys = [Rq(coeff_list) for coeff_list in coeff_lists]

    vec = sg.vector(Rq, polys)

    assert norm_rq_vector(vec) == sqrt(sum_coeffs)


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
        assert norm_rq_vector(
            sample_randomness_or_proof()) <= B_OR_PRIME, "OR-proof randomness should have small norm"


def test_random_valid_proofs(iterations=1000):
    """
        Test OR-proof generation and verification for a random m in {0,1} multiple times to ensure it works repeatedly.
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
    # Commitment Scheme
    test_commitment_scheme()
    test_commitment_homomorphism()
    test_commitment_randomness_holds_bound()

    # OR-proof
    test_tampered_proof()
    test_valid_proofs()
    test_invalid_proof(-1)
    test_invalid_proof(3)
    test_invalid_proof(346334343)
    test_or_proof_randomness_holds_bound()

    # Mixed
    test_tampered_commitment()
    test_mismatch_invalid_commitment_valid_proof()
    test_mismatch_valid_commitment_invalid_proof()
    test_mismatch_valid_commitment_valid_proof()

    # Helper functions
    test_generating_and_validating_challenge_polynomial()
    test_reject_challenge_polynomial_with_too_many_zeroes()
    test_reject_challenge_polynomial_with_invalid_entries()
    test_norm_rq_vector()

    # These tests may run a long time depending on the chosen amount of iterations
    test_random_valid_proofs()
    test_rejection_sampling()

    print("All tests passed!")
