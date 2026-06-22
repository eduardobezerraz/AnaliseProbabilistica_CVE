import os
import json
import pandas as pd

BASE_DIR = "../cves"
OUTPUT_FILE = "../resultados/dataset.csv"

COLUMNS = [
    "CVE_ID",
    "Year",
    "CVSS_Score",
    "Severity",
    "Attack_Vector",
    "Attack_Complexity",
    "Privileges_Required",
    "User_Interaction",
    "Confidentiality_Impact",
    "Integrity_Impact",
    "Availability_Impact",
    "Automatable"
]


# -------------------------
# FILTRO PRINCIPAL (2023–2026 + 0001–0999)
# -------------------------
def is_valid_cve(cve_id):
    try:
        year = int(cve_id.split("-")[1])
        number = int(cve_id.split("-")[2])

        return 2023 <= year <= 2026 and 1 <= number <= 999
    except:
        return False


def safe_get(data, path):
    try:
        for p in path:
            data = data[p]
        return data
    except:
        return None


def extract(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    cve_id = safe_get(data, ["cve", "id"])

    if not cve_id or not is_valid_cve(cve_id):
        return None

    metrics = safe_get(data, ["cve", "metrics", "cvssMetricV31"])
    if not metrics:
        metrics = safe_get(data, ["cve", "metrics", "cvssMetricV30"])

    if metrics:
        cvss = metrics[0]["cvssData"]
        score = cvss.get("baseScore")
        severity = cvss.get("baseSeverity")
        vector = cvss.get("attackVector")
        complexity = cvss.get("attackComplexity")
        privileges = cvss.get("privilegesRequired")
        user_int = cvss.get("userInteraction")
        conf = cvss.get("confidentialityImpact")
        integ = cvss.get("integrityImpact")
        avail = cvss.get("availabilityImpact")
    else:
        score = severity = vector = complexity = privileges = user_int = conf = integ = avail = None

    return [
        cve_id,
        int(cve_id.split("-")[1]),
        score,
        severity,
        vector,
        complexity,
        privileges,
        user_int,
        conf,
        integ,
        avail,
        safe_get(data, ["cve", "containers", "cna", "metrics", 0, "automatable"])
    ]


def main():
    rows = []

    # ✔ SOMENTE 2023–2026
    for year in range(2023, 2027):
        path = os.path.join(BASE_DIR, str(year))

        if not os.path.exists(path):
            continue

        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".json"):
                    result = extract(os.path.join(root, file))
                    if result:
                        rows.append(result)

    df = pd.DataFrame(rows, columns=COLUMNS)

    os.makedirs("../resultados", exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    print(f"[OK] Dataset gerado com {len(df)} registros (2023–2026)")


if __name__ == "__main__":
    main()