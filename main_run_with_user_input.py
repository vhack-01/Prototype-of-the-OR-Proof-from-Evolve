from simulate_or_proof import simulate_or_proof

# --------------------------------------------------------
#  Prompt the user to enter value for m and simulate an OR-proof for it
# --------------------------------------------------------

if __name__ == "__main__":
    m = int(input("Enter your vote (valid are 0 or 1): "))

    print(f"Simulating OR-proof for m = {m}")

    is_m_valid = simulate_or_proof(m)

    if is_m_valid:
        print("✅ OR-proof valid")
    else:
        print("❌ OR-proof not valid")
