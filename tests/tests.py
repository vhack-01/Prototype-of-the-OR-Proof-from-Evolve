import sage.all as sg
from commitment.commitment import open, commit, generate_commitment_key
from or_proof.prover import generate_or_proof
from or_proof.verifier import verify_or_proof
from config.ring import Rq
from simulate_or_proof import simulate_or_proof

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
        Test OR‑proof generation and verification for m = 0 and m = 1.
    """
    print("Testing valid OR‑proofs...")

    for m in (0, 1):
        # Generate proof
        C = generate_commitment_key()
        c, r = commit(C, m)
        r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

        # Verify proof
        assert verify_or_proof(C, c, r0, r1, f0, f1), f"Proof for m={m} should be valid"

        print(f"  m = {m}: OK")


def test_random_valid_proofs(iterations=1000):
    """
        Test OR‑proof generation and verification for a random m in {0,1} multiple times to ensure it works repeatedly.
    """
    print("Testing valid OR‑proofs...")

    for i in range(iterations):
        m = random.randint(0, 1)
        C = generate_commitment_key()
        c, r = commit(C, m)
        r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

        assert verify_or_proof(C, c, r0, r1, f0, f1), f"Proof for m={m} should be valid"


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


def test_rejection_sampling(iterations=1000):
    """
        According to the paper, it should take on average 3 tries to generate an OR-proof. Generate 'iteration' OR-proofs and
        calculate the mean.

        Args:
            iterations: number of OR-proofs to simulate
    """
    print(f"Simulating {iterations} OR-proofs to test rejection sampling...")

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

    # Calculate average attempts
    avg_attempts = attempts_counter / iterations

    assert 2.5 < avg_attempts < 3.5, f"Average attempts should be ~3, got {avg_attempts:.2f}"

    # Output results
    print(f"    Average attempts needed to generate a proof: {avg_attempts:.2f}")


if __name__ == "__main__":
    # Commitment Scheme
    test_mismatch_invalid_commitment_valid_proof()
    test_mismatch_valid_commitment_invalid_proof()
    test_mismatch_valid_commitment_valid_proof()
    test_tampered_commitment()
    test_commitment_scheme()
    test_commitment_homomorphism()

    # OR-proof
    test_tampered_proof()
    test_valid_proofs()
    test_invalid_proof(-1)
    test_invalid_proof(3)
    test_invalid_proof(346334343)

    # These tests may run a long time depending on the chosen amount of iterations
    # test_random_valid_proofs()
    # test_rejection_sampling()

    print("All tests passed!")
