import os
import json
import pandas as pd

BASE_DIR = "../cves"
OUTPUT_CSV = "../resultados/dataset.csv"
OUTPUT_XLSX = "../resultados/dataset.xlsx"

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
# FILTRO CVE (2023–2026 / 0001–0999)
# -------------------------
def is_valid_cve(cve_id):
    try:
        parts = cve_id.split("-")
        if len(parts) != 3:
            return False

        year = int(parts[1])
        number = int(parts[2])

        return 2023 <= year <= 2026 and 1 <= number <= 999

    except Exception:
        return False


def safe_get(data, path):
    try:
        for p in path:
            data = data[p]
        return data
    except Exception:
        return None


# -------------------------
# PEGAR MÉTRICAS DE QUALQUER CONTAINER (cna + adp, dict ou list)
# -------------------------
def get_metrics(data):
    containers = data.get("containers", {}) or {}

    metrics = []

    # ---- CNA ----
    cna = containers.get("cna")
    if isinstance(cna, dict):
        metrics += cna.get("metrics", []) or []

    # ---- ADP (pode ser dict OU list, dependendo do CVE) ----
    adp = containers.get("adp")

    if isinstance(adp, dict):
        metrics += adp.get("metrics", []) or []

    elif isinstance(adp, list):
        for item in adp:
            if isinstance(item, dict):
                metrics += item.get("metrics", []) or []

    # garante que só ficam dicts na lista (alguns registros trazem lixo)
    return [m for m in metrics if isinstance(m, dict)]


# -------------------------
# PEGAR CVSS (v4.0 → v3.1 → v3.0 → v2.0)
# Aceita as duas grafias de chave que aparecem no cvelistV5
# -------------------------
CVSS_KEYS_BY_PRIORITY = [
    ("4.0", ["cvssV4_0", "cvssV4"]),
    ("3.1", ["cvssV3_1", "cvssV3.1"]),
    ("3.0", ["cvssV3_0", "cvssV3.0", "cvssV3"]),
    ("2.0", ["cvssV2_0", "cvssV2"]),
]


def get_cvss(metrics):
    if not metrics:
        return None, None

    for version_label, possible_keys in CVSS_KEYS_BY_PRIORITY:
        for m in metrics:
            for key in possible_keys:
                if key in m and isinstance(m[key], dict):
                    return m[key], version_label

    return None, None


# -------------------------
# PEGAR "Automatable" (vem em metrics como {"other": {"type": "Automatable", ...}})
# Pode também aparecer dentro de métricas SSVC, então cobrimos os dois formatos.
# -------------------------
def get_automatable(metrics):
    for m in metrics:
        other = m.get("other")
        if isinstance(other, dict) and other.get("type") == "Automatable":
            content = other.get("content")
            if isinstance(content, dict):
                return content.get("value")
            return content

        ssvc = m.get("ssvc")
        if not isinstance(ssvc, dict) and isinstance(other, dict):
            ssvc = other.get("content")

        if isinstance(ssvc, dict):
            options = ssvc.get("options") or []
            for opt in options:
                if isinstance(opt, dict) and "Automatable" in opt:
                    return opt.get("Automatable")

    return None


# -------------------------
# EXTRAÇÃO PRINCIPAL
# -------------------------
def extract(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
        print(f"[ERROR] Falha ao ler {file_path}: {e}")
        return None, "error"

    if not isinstance(data, dict):
        return None, "error"

    cve_id = safe_get(data, ["cveMetadata", "cveId"])

    if not cve_id or not is_valid_cve(cve_id):
        return None, "fora_do_escopo"

    # CVEs REJECTED/RESERVED vêm quase vazios (sem CVSS real) — contamos
    # separadamente em vez de descartar sem registrar, para que o número
    # bruto (~4.000, conforme README) e o número "limpo" sejam ambos visíveis.
    state = safe_get(data, ["cveMetadata", "state"])
    if state and state != "PUBLISHED":
        return None, "rejected_reserved"

    metrics = get_metrics(data)
    cvss, cvss_version = get_cvss(metrics)

    if cvss:
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

    automatable = get_automatable(metrics)

    row = [
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
        automatable
    ]

    return row, "ok"


# -------------------------
# MAIN
# -------------------------
def main():
    rows = []
    total_files = 0
    skipped_errors = 0
    skipped_rejected = 0
    skipped_fora_escopo = 0

    for year in range(2023, 2027):
        path = os.path.join(BASE_DIR, str(year))

        if not os.path.exists(path):
            print(f"[WARN] Pasta não encontrada: {year}")
            continue

        print(f"\n[INFO] Processando ano {year}...")

        year_count = 0

        # No cvelistV5, cada ano é dividido em subpastas por milhar
        # (0xxx, 1xxx, 2xxx...). Como só queremos 0001-0999, lemos
        # direto a pasta 0xxx em vez de percorrer o ano inteiro.
        target_subdir = os.path.join(path, "0xxx")

        if not os.path.exists(target_subdir):
            print(f"[WARN] Subpasta 0xxx não encontrada em {year}, "
                  f"caindo para busca completa (mais lenta)...")
            scan_dirs = [d for d, _, _ in os.walk(path)]
        else:
            scan_dirs = [target_subdir]

        for scan_dir in scan_dirs:
            for file in os.listdir(scan_dir):
                if not file.endswith(".json"):
                    continue

                total_files += 1

                try:
                    row, status = extract(os.path.join(scan_dir, file))
                except Exception as e:
                    print(f"[ERROR] Falha inesperada em {file}: {e}")
                    row, status = None, "error"

                if status == "ok":
                    rows.append(row)
                    year_count += 1
                elif status == "rejected_reserved":
                    skipped_rejected += 1
                elif status == "fora_do_escopo":
                    skipped_fora_escopo += 1
                elif status == "error":
                    skipped_errors += 1

                if total_files % 500 == 0:
                    print(f"[PROGRESS] Arquivos: {total_files} | Registros válidos: {len(rows)}")

        print(f"[OK] Ano {year} finalizado | válidos: {year_count}")

    print("\n[INFO] Gerando dataset...")

    df = pd.DataFrame(rows, columns=COLUMNS)

    os.makedirs("../resultados", exist_ok=True)
    # sep=";" porque o Excel em locale PT-BR usa "," como separador decimal
    # e por isso espera ";" como separador de campos no CSV. Sem isso, o
    # Excel não quebra as colunas automaticamente ao abrir o arquivo.
    df.to_csv(OUTPUT_CSV, index=False, sep=";")
    df.to_excel(OUTPUT_XLSX, index=False)

    bruto = len(rows) + skipped_rejected
    print(f"[OK] Dataset gerado: {OUTPUT_CSV} e {OUTPUT_XLSX}")
    print(f"[OK] Registros válidos (PUBLISHED, com CVSS quando disponível): {len(df)}")
    print(f"[OK] Registros brutos no escopo CVE-YYYY-0001..0999 (válidos + rejected/reserved): {bruto}")
    print(f"[INFO] Descartados por REJECTED/RESERVED: {skipped_rejected}")
    print(f"[INFO] Fora do escopo (ano/número fora do filtro): {skipped_fora_escopo}")
    print(f"[INFO] Erros de leitura/parse: {skipped_errors}")
    print(f"[INFO] Total de arquivos .json percorridos: {total_files}")


if __name__ == "__main__":
    main()