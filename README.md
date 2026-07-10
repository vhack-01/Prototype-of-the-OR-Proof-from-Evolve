# Prototypical implementation of the OR-proof from 'EVOLVE'

This repository contains a prototypical implementation of the **OR-proof** described in the paper  
"Practical Quantum-Safe Voting from Lattices" (see [References](#references)). The OR-proof allows a prover to
demonstrate that a lattice-based commitment opens to either **0** or **1**,
without revealing which, and without leaking the witness.

The main protocol flow can be found
in ``simulate_or_proof.py``. All proof parameters are defined in ``config/params.py``, following the values from the
paper.

## Requirements

- **[SageMath](https://www.sagemath.org/) 10.8** (includes Python
  3.14.4)
    - for Installation see [here](https://doc.sagemath.org/html/en/installation/index.html)

All commands described below must be executed inside a SageMath environment.

## Usage

- Run the desired main script from the project root:
  ```bash
  python <file_name>.py
  ```
- ``main_run_in_range.py`` simulates an OR-proof for every m in the hardcoded range (adjustable by editing line 14)
- ``main_run_with_random_input.py`` simulates an OR-proof for 0 or 1 (chosen randomly)
- ``main_run_with_user_input.py`` simulates an OR-proof for the value entered by the user

## Benchmarking

- The benchmarking functions can be found in ``benchmark/benchmark.py``.
- They can be executed from the project root by calling:
  ```bash
  python -m benchmark.benchmark
  ```

## Tests

- Various test functions can be found in ``tests/tests.py``.
- They can be executed from the project root by calling:
  ```bash
  python -m tests.tests
  ```

## References

- Rafaël del Pino, Vadim Lyubashevsky, Gregory Neven, and
  Gregor Seiler. 2017. Practical Quantum-Safe Voting from Lattices. In Proceedings of the 2017 ACM SIGSAC Conference
  on Computer and Communications Security (CCS '17). Association for Computing Machinery, New York, NY, USA, 1565-1581.
  https://doi.org/10.1145/3133956.3134101