from simulate_or_proof import simulate_or_proof

# --------------------------------------------------------
#  Simulate an OR-proof for all values for m in the range defined in line 14
# --------------------------------------------------------


if __name__ == "__main__":

    for m in range(-10, 10):
        print("----------------------")
        print(f"Simulating OR-proof for m = {m}")

        is_m_valid = simulate_or_proof(m)

        if is_m_valid:
            print("✅ OR-proof valid")
        else:
            print("❌ OR-proof not valid")
