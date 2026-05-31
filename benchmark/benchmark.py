import time
import struct
from datetime import datetime

import sage.all as sg

from commitment.commitment import generate_commitment
from or_proof.prover import generate_or_proof
from or_proof.verifier import verify_or_proof
from simulate_or_proof import simulate_or_proof
from utils.shared_utils import center_coefficient, serialize_rq_vector


# --------------------------------------------------------
#  Functions for benchmarking
# --------------------------------------------------------

def serialize_challenge(f):
    """
        Serialize a challenge polynomial.

        Args:
            f: challenge polynomial

        Returns:
            serialized polynomial as 60 indices (2 bytes each) followed by a 8‑byte sign mask
    """
    coeffs = f.list()
    indices = []
    signs = 0
    bit = 0
    for i, c in enumerate(coeffs):
        if c != 0:
            indices.append(i)
            if center_coefficient(c) == -1:
                signs |= (1 << bit)
            bit += 1
    # 60 indices as unsigned shorts (2 bytes each)
    data = struct.pack('<' + 'H' * 60, *indices)
    # 8 bytes for signs
    data += struct.pack('<Q', signs)
    return data


def benchmark_proof_size():
    """
        Run benchmarking for the proof size.
    """
    print("Benchmarking proof size")
    # Each proof has the same size, so running it once is enough.
    C, c, r = generate_commitment(0)
    r0, r1, f0, f1, _ = generate_or_proof(0, C, c, r)

    proof_bytes = serialize_rq_vector(r0) + serialize_rq_vector(r1) + serialize_challenge(f0) + serialize_challenge(f1)
    proof_size = len(proof_bytes)
    print(f"    Proof size: {proof_size:.0f} bytes ({proof_size / 1024:.1f} KB)")


def benchmark_run_times(iterations=1000):
    """
        Run benchmarking for the run times.

        Args:
            iterations: number of OR-proofs to simulate during benchmarking
    """
    current_time_start = datetime.now().strftime("%H:%M:%S")
    print(f"Benchmarking of run times started at {current_time_start} | Running {iterations} iterations")

    times_prover = []
    times_verifier = []
    attempts_counter = 0

    # Warm-up
    for _ in range(3):
        simulate_or_proof(0)

    for _ in range(iterations):
        C, c, r = generate_commitment(0)

        # Measure generation time
        gen_start = time.perf_counter()
        r0, r1, f0, f1, attempts = generate_or_proof(0, C, c, r)
        gen_end = time.perf_counter()
        times_prover.append(gen_end - gen_start)
        attempts_counter += attempts

        # Measure verification time
        verify_start = time.perf_counter()
        is_valid = verify_or_proof(C, c, r0, r1, f0, f1)
        verify_end = time.perf_counter()
        times_verifier.append(verify_end - verify_start)

        assert is_valid, "Proof verification failed"

    # Calculate averages
    avg_time_prover = sum(times_prover) / len(times_prover)
    avg_time_verifier = sum(times_verifier) / len(times_verifier)
    avg_attempts = attempts_counter / iterations

    # Output results
    print(f"    Average proof generation time: {avg_time_prover:.6f}s")
    print(f"    Average proof verification time: {avg_time_verifier:.6f}s")
    print(f"    Average attempts needed to generate a proof: {avg_attempts:.2f}")

    current_time_end = datetime.now().strftime("%H:%M:%S")
    print("Benchmarking of run times finished at", current_time_end)


if __name__ == "__main__":
    benchmark_proof_size()
    benchmark_run_times()
