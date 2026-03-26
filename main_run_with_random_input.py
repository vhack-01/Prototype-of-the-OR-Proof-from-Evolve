import random
from datetime import datetime

from simulate_or_proof import simulate_or_proof

# --------------------------------------------------------
#  Simulate an OR-proof for m being 0 or 1 (chosen randomly at runtime)
# --------------------------------------------------------

if __name__ == "__main__":
    m = random.choice([0, 1])

    current_time = datetime.now().strftime("%H:%M:%S")
    print("Current Time Start =", current_time)

    print(f"Simulating OR-proof for m = {m}")

    is_m_valid = simulate_or_proof(m)

    if is_m_valid:
        print("✅ OR-proof valid")
    else:
        print("❌ OR-proof not valid")

    current_time2 = datetime.now().strftime("%H:%M:%S")
    print("Current Time End =", current_time2)
