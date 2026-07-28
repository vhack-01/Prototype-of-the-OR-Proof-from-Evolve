import random

from commitment import commitment
from or_proof import prover, verifier
from config.params import N_A, Q


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
    # Create a public commitment key (usually it is public and given to the voter)
    C = commitment.generate_commitment_key()

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

    # Verify the OR-proof
    is_valid = verifier.verify_or_proof(C, summed_commitments, r0, r1, f0, f1)

    return is_valid


def split_vote(v_i):
    """
    Splits a vote v_i (should 0 or 1) into N_A additive shares modulo Q.

    Args:
        v_i: The vote

    Returns:
        A list of N_A integers, each in [0, Q-1].
        The sum of these shares modulo Q equals v_i.
    """
    shares = []

    # Generate the first N_A - 1 shares uniformly at random modulo Q
    for _ in range(N_A - 1):
        share = random.randrange(Q)  # picks an integer from 0 to Q-1 inclusive
        shares.append(share)

    # Compute the final share so that total_sum ≡ v_i (mod Q)
    last_share = (v_i - sum(shares)) % Q
    shares.append(last_share)

    return shares
