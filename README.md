# Prototypical Implementation of the OR-proof from 'EVOLVE'

This repository contains a prototypical implementation of the commitment scheme and **OR-proof** described in the
paper  
"Practical Quantum-Safe Voting from Lattices" (see [References](#references)). The OR-proof allows a prover to
demonstrate that a lattice-based commitment opens to either **0** or **1**,
without revealing which, and without leaking the witness.

The main protocol flow can be found
in ``simulate_or_proof.py``. All proof parameters are defined in ``config/params.py``, following the values from the
paper.

**Security Notice**:
This implementation is for demonstration and educational purposes only. It is **not constant-time** and has not
undergone any security review. Do **not** use it in any
production system or real election.

## Requirements & Installation

- **[SageMath](https://www.sagemath.org/) 10.8** (includes Python
  3.14.4)
    - for Installation see [here](https://doc.sagemath.org/html/en/installation/index.html)

1. Install SageMath 10.8.
2. Clone this repository.
3. Run all commands from the project root **inside the SageMath shell**

## Project Structure

- `config/` – ring definitions and all protocol parameters.
- `commitment/` – homomorphic commitment scheme (Keygen, Commit, Open).
- `or_proof/` – prover and verifier algorithm for the OR-proof.
- `utils/` – Gaussian sampling, Fiat-Shamir transform, general helper functions.
- `tests/` – unit and integration tests.
- `benchmark/` – runtime and size measurements.
- `simulate_or_proof.py` – simulation of an OR-proof, using the implemented components.
- `main_*.py` – entry-point scripts for different usage scenarios.

## Usage

- Run the desired main script from the project root:
  ```bash
  python <file_name>.py
  ```
- ``main_run_in_range.py`` simulates an OR-proof for every m in the hardcoded range (adjustable by editing line 10)
- ``main_run_with_random_input.py`` simulates an OR-proof for 0 or 1 (chosen randomly)
- ``main_run_with_user_input.py`` simulates an OR-proof for the value entered by the user

## Tests

- Various test functions can be found in ``tests/tests.py``.
- They can be executed from the project root by calling:
  ```bash
  python -m tests.tests
  ```
- The line coverage is 100% (excluding the entry-point scripts, and the tests/benchmark module), measured
  using ``coverage``. A configuration file ``.coveragerc`` has been added to the
  repository for convenience. The coverage can be checked by running the following command from project root:

```bash
  coverage run -m tests.tests
  coverage report -m
```

## Benchmarking

- The benchmarking functions can be found in ``benchmark/benchmark.py``. They measure the average runtime of commitment
  key generation, commiting, opening, OR-proof generation and verification (over 11000 iterations by default), as well
  as the size of a commitment and the full OR-proof (in bytes).
- They can be executed from the project root by calling:
  ```bash
  python -m benchmark.benchmark
  ```

## References

- Rafaël del Pino, Vadim Lyubashevsky, Gregory Neven, and
  Gregor Seiler. 2017. Practical Quantum-Safe Voting from Lattices. In Proceedings of the 2017 ACM SIGSAC Conference
  on Computer and Communications Security (CCS '17). Association for Computing Machinery, New York, NY, USA, 1565-1581.
  https://doi.org/10.1145/3133956.3134101