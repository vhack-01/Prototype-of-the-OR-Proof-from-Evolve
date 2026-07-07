from commitment import commitment
from or_proof import prover, verifier


# --------------------------------------------------------
#  Simulation of the OR-proof
# --------------------------------------------------------

def simulate_or_proof(m):
    """
        Simulate an OR-proof for the message m.

        Args:
            m: the message

        Returns:
            True if the OR-proof was valid, False otherwise.
    """
    C = commitment.generate_commitment_key()
    c, r = commitment.commit(C,m)

    r0, r1, f0, f1, _ = prover.generate_or_proof(m, C, c, r)

    is_valid = verifier.verify_or_proof(C, c, r0, r1, f0, f1)

    return is_valid
