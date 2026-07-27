import time
import struct
from datetime import datetime

from commitment.commitment import generate_commitment_key, commit, open
from or_proof.prover import generate_or_proof
from or_proof.verifier import verify_or_proof
from simulate_or_proof import simulate_or_proof
from utils.shared_utils import serialize_rq_vector
from config.params import N_A


# --------------------------------------------------------
#  Functions for Benchmarking
#  The main function can be found at the end of the file.
# --------------------------------------------------------


def benchmark_proof_size():
    """
    Measure the size of a voter's contribution to the bulletin board (one OR-proof, one commitment per authority).
    """
    print("Benchmarking voter-side sizes")

    # Generate one commitment and its OR-proof (size is independent of message)
    C = generate_commitment_key()
    c, r = commit(C, 0)
    r0, r1, f0, f1, _ = generate_or_proof(0, C, c, r)

    # Size of the commitment (c)
    commitment_size = len(serialize_rq_vector(c))
    print(f"    Commitment size (per authority): {commitment_size / 1024:.1f} KB")

    # Size of the OR-proof (r0, r1, f0, f1)
    proof_bytes = (serialize_rq_vector(r0) +
                   serialize_rq_vector(r1) +
                   serialize_challenge(f0) +
                   serialize_challenge(f1))
    proof_size = len(proof_bytes)
    print(f"    OR-proof size: {proof_size / 1024:.1f} KB")

    # Voter totals
    total = N_A * commitment_size + proof_size
    avg_per_authority_no_cipher = total / N_A

    print(f"\nVoter contribution ({N_A} commitments + OR-proof):")
    print(f"    Total size: {total / 1024:.1f} KB")
    print(f"    Average per authority: {avg_per_authority_no_cipher / 1024:.1f} KB")


def benchmark_run_times(iterations=11000):
    """
        Run benchmarking for the run times.

        Args:
            iterations: number of OR-proofs to simulate during benchmarking
    """
    current_time_start = datetime.now().strftime("%H:%M:%S")
    print(f"Benchmarking of run times started at {current_time_start} | Running {iterations} iterations")

    times_key = []
    times_commit = []
    times_open = []
    times_prover = []
    times_verifier = []

    # Warm-up
    for _ in range(3):
        simulate_or_proof(0)
        simulate_or_proof(1)

    for _ in range(iterations):
        # Measure commitment key generation time
        key_start = time.perf_counter()
        C = generate_commitment_key()
        key_end = time.perf_counter()
        times_key.append(key_end - key_start)

        # Measure commitment generation time
        commit_start = time.perf_counter()
        c, r = commit(C, 0)
        commit_end = time.perf_counter()
        times_commit.append(commit_end - commit_start)

        # Measure commitment opening time
        open_start = time.perf_counter()
        open(C, c, r)
        open_end = time.perf_counter()
        times_open.append(open_end - open_start)

        # Measure proof generation time
        gen_start = time.perf_counter()
        r0, r1, f0, f1, attempts = generate_or_proof(0, C, c, r)
        gen_end = time.perf_counter()
        times_prover.append(gen_end - gen_start)

        # Measure proof verification time
        verify_start = time.perf_counter()
        verify_or_proof(C, c, r0, r1, f0, f1)
        verify_end = time.perf_counter()
        times_verifier.append(verify_end - verify_start)

    # Calculate averages
    avg_time_key = sum(times_key) / len(times_key)
    avg_time_commit = sum(times_commit) / len(times_commit)
    avg_time_open = sum(times_open) / len(times_open)
    avg_time_prover = sum(times_prover) / len(times_prover)
    avg_time_verifier = sum(times_verifier) / len(times_verifier)

    # Output results
    print(f"    Average commitment key generation time: {avg_time_key * 1000:.0f} ms")
    print(f"    Average commit time: {avg_time_commit * 1000:.0f} ms")
    print(f"    Average open time: {avg_time_open * 1000:.0f} ms")
    print(f"    Average proof generation time: {avg_time_prover * 1000:.0f} ms")
    print(f"    Average proof verification time: {avg_time_verifier * 1000:.0f} ms")

    voter_time = N_A * avg_time_commit + avg_time_prover
    print(f"\nVoter time ({N_A} commitments + one OR-proof):")
    print(f"    Total time: {voter_time * 1000:.0f} ms")

    current_time_end = datetime.now().strftime("%H:%M:%S")
    print("Benchmarking of run times finished at", current_time_end)


# --------------------------------------------------------
#  Helper Functions for Benchmarking
# --------------------------------------------------------

def serialize_challenge(f):
    """
        Serialize a challenge polynomial.

        Args:
            f: challenge polynomial

        Returns:
            serialized polynomial as 60 indices (2 bytes each) followed by an 8-byte sign mask
    """
    coeffs = f.list()
    indices = []
    signs = 0
    bit = 0

    for i, c in enumerate(coeffs):
        if c != 0:
            indices.append(i)
            if c.lift_centered() == -1:
                signs |= (1 << bit)
            bit += 1

    data = struct.pack('<' + 'H' * 60, *indices)  # 60 indices as unsigned shorts (2 bytes each)
    data += struct.pack('<Q', signs)  # 8 bytes for signs

    return data


if __name__ == "__main__":
    benchmark_proof_size()
    benchmark_run_times(11000)
