import sage.all as sg
from commitment.commitment import generate_commitment
from or_proof.prover import generate_or_proof
from or_proof.verifier import verify_or_proof
from config.ring import Rq

# Set deterministic seed so tests are reproducible
SEED = 42
import random

random.seed(SEED)

from sage.misc.randstate import set_random_seed

set_random_seed(SEED)


# --------------------------------------------------------
#  Functions for running tests
# --------------------------------------------------------

def test_valid_proofs():
    """
        Test OR‑proof generation and verification for m = 0 and m = 1.
    """
    print("Testing valid OR‑proofs...")
    for m in (0, 1):
        C, c, r = generate_commitment(m)
        r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)
        assert verify_or_proof(C, c, r0, r1, f0, f1), f"Proof for m={m} should be valid"
        print(f"  m = {m}: OK")


def test_tampered_proof():
    """
        Tamper with a proof and verify that it is rejected.
    """
    print(f"Testing valid OR-proof that has been tampered with...")
    m = 0
    C, c, r = generate_commitment(m)
    r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)

    # Modify r0 (e.g., add a random polynomial to the first entry)
    modified_r0 = list(r0)
    modified_r0[0] += Rq.random_element()
    modified_r0 = sg.vector(Rq, modified_r0)

    assert not verify_or_proof(C, c, modified_r0, r1, f0, f1), "Tampered proof should be invalid"
    print("  Invalid proof correctly rejected")


def test_invalid_proof(m):
    """
        Create a commitment to a message not in {0,1} and try to prove it; should fail.
    """
    print("Testing proof for an invalid message ...")
    C, c, r = generate_commitment(m)
    r0, r1, f0, f1, _ = generate_or_proof(m, C, c, r)
    assert not verify_or_proof(C, c, r0, r1, f0, f1), f"Proof for m={m} should be invalid"


if __name__ == "__main__":
    test_tampered_proof()
    test_valid_proofs()
    test_invalid_proof(-1)
    test_invalid_proof(3)
    test_invalid_proof(346334343)
    print("All tests passed!")
