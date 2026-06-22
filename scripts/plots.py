import pandas as pd
import matplotlib.pyplot as plt

df = pd.read_csv("../resultados/dataset.csv")

# ---------------- CVSS ----------------
plt.figure()
df["CVSS_Score"].dropna().astype(float).hist(bins=20)
plt.title("CVSS Score (2023–2026)")
plt.savefig("../resultados/cvss_hist.png")

# ---------------- SEVERITY ----------------
plt.figure()
df["Severity"].value_counts().plot(kind="bar")
plt.title("Severity Distribution (2023–2026)")
plt.savefig("../resultados/severity.png")

# ---------------- ATTACK VECTOR ----------------
plt.figure()
df["Attack_Vector"].value_counts().plot(kind="bar")
plt.title("Attack Vector (2023–2026)")
plt.savefig("../resultados/attack_vector.png")

# ---------------- AUTOMATABLE ----------------
plt.figure()
df["Automatable"].value_counts().plot(kind="pie", autopct="%1.1f%%")
plt.title("Automatable (2023–2026)")
plt.ylabel("")
plt.savefig("../resultados/automatable.png")

print("[OK] Gráficos gerados (2023–2026)")