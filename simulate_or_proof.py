from commitment import commitment
from or_proof import prover, verifier
from utils.shared_utils import split_vote


# --------------------------------------------------------
#  Simulation of an OR-proof/Voter
# --------------------------------------------------------

def simulate_or_proof(m):
    """
        Simulate an OR-proof for the message m.

        Args:
            m: the message

        Returns:
            True if the OR-proof was valid, False otherwise.
    """
    # Setup: Create a public commitment key
    C = commitment.generate_commitment_key()

    # Vote: Simulate a voter
    r0, r1, f0, f1, c = simulate_voter(C, m)

    # Tally/Verify: Verify the OR-proof that was created by the voter
    is_valid = verifier.verify_or_proof(C, c, r0, r1, f0, f1)

    return is_valid


def simulate_voter(C, m):
    """
        Simulate a voter that votes for the message m. Implements the Vote_i algorithm from EVOLVE paper section 4.1.

        Args:
            m: the vote

        Returns:
            two opening vectors (r0, r1)
            two challenge polynomials (f0, f1)
            the summed of all commitment shares
    """
    # (1) Split the vote into N_A shares
    vote_list = split_vote(m)

    # (2) + (3) Calculate a commitment for each share and store it together with the used randomness
    commitments = []
    randomness = []
    for vote in vote_list:
        c, r = commitment.commit(C, vote)
        commitments.append(c)
        randomness.append(r)

    # (4) + (5) Sum all commitments and randomness
    summed_commitments = sum(commitments)
    summed_randomness = sum(randomness)

    # (6) Generate the OR-proof
    r0, r1, f0, f1, _ = prover.generate_or_proof(m, C, summed_commitments, summed_randomness)

    # (7) - (9) Encrypt each randomness and post them + all commitments + OR-proof to the bulletin board
    # out of scope for this implementation

    return r0, r1, f0, f1, summed_commitments
