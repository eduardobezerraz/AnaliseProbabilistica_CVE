import os
import pandas as pd
import matplotlib.pyplot as plt

INPUT_CSV = "../resultados/dataset.csv"
OUTPUT_DIR = "../resultados"


def load_dataset():
    df = pd.read_csv(INPUT_CSV, sep=";")
    return df


def normalizar_colunas_texto(df):
    colunas_categoricas = [
        "Severity",
        "Attack_Vector",
        "Attack_Complexity",
        "Privileges_Required",
        "User_Interaction",
    ]

    for col in colunas_categoricas:
        if col in df.columns:
            df[col] = df[col].astype(str).str.strip().str.upper()
            df[col] = df[col].replace({"NAN": pd.NA, "": pd.NA})

    if "Automatable" in df.columns:
        df["Automatable"] = df["Automatable"].astype(str).str.strip().str.lower()
        df["Automatable"] = df["Automatable"].replace({"nan": pd.NA, "none": pd.NA, "": pd.NA})

    return df


def salvar(fig, nome_arquivo):
    caminho = os.path.join(OUTPUT_DIR, nome_arquivo)
    fig.savefig(caminho, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[OK] Gráfico salvo: {caminho}")


# -------------------------
# Histograma do CVSS Score
# -------------------------
def plot_cvss_hist(df):
    score = df["CVSS_Score"].dropna()

    if score.empty:
        print("[WARN] Sem dados de CVSS_Score para plotar histograma.")
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(score, bins=20, color="#4C72B0", edgecolor="black")
    ax.set_title("Distribuição do CVSS Score")
    ax.set_xlabel("CVSS Score")
    ax.set_ylabel("Frequência")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    salvar(fig, "cvss_hist.png")


# -------------------------
# Distribuição de Severity
# -------------------------
def plot_severity(df):
    contagem = df["Severity"].dropna().value_counts()

    if contagem.empty:
        print("[WARN] Sem dados de Severity para plotar.")
        return

    ordem = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    contagem = contagem.reindex([c for c in ordem if c in contagem.index])

    fig, ax = plt.subplots(figsize=(7, 5))
    cores = {"LOW": "#55A868", "MEDIUM": "#DDB95B", "HIGH": "#DD8452", "CRITICAL": "#C44E52"}
    barras_cores = [cores.get(s, "#4C72B0") for s in contagem.index]

    ax.bar(contagem.index, contagem.values, color=barras_cores, edgecolor="black")
    ax.set_title("Distribuição de Severidade")
    ax.set_xlabel("Severity")
    ax.set_ylabel("Quantidade")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    salvar(fig, "severity.png")


# -------------------------
# Distribuição de Attack Vector
# -------------------------
def plot_attack_vector(df):
    contagem = df["Attack_Vector"].dropna().value_counts()

    if contagem.empty:
        print("[WARN] Sem dados de Attack_Vector para plotar.")
        return

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.bar(contagem.index, contagem.values, color="#4C72B0", edgecolor="black")
    ax.set_title("Distribuição de Attack Vector")
    ax.set_xlabel("Attack Vector")
    ax.set_ylabel("Quantidade")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    salvar(fig, "attack_vector.png")


# -------------------------
# Distribuição de Automatable
# -------------------------
def plot_automatable(df):
    contagem = df["Automatable"].dropna().value_counts()

    if contagem.empty:
        print("[WARN] Sem dados de Automatable para plotar.")
        return

    fig, ax = plt.subplots(figsize=(6, 5))
    cores = {"yes": "#C44E52", "no": "#55A868"}
    barras_cores = [cores.get(v, "#4C72B0") for v in contagem.index]

    ax.bar(contagem.index, contagem.values, color=barras_cores, edgecolor="black")
    ax.set_title("Exploração Automatizável (Automatable)")
    ax.set_xlabel("Automatable")
    ax.set_ylabel("Quantidade")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    salvar(fig, "automatable.png")


# -------------------------
# Extras (não exigidos pelo README, mas úteis para as questões
# de pesquisa sobre Privileges_Required e evolução por ano)
# -------------------------
def plot_privileges_required(df):
    contagem = df["Privileges_Required"].dropna().value_counts()

    if contagem.empty:
        return

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.bar(contagem.index, contagem.values, color="#8172B2", edgecolor="black")
    ax.set_title("Distribuição de Privileges Required")
    ax.set_xlabel("Privileges Required")
    ax.set_ylabel("Quantidade")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    salvar(fig, "privileges_required.png")


def plot_por_ano(df):
    contagem = df["Year"].value_counts().sort_index()

    if contagem.empty:
        return

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.bar(contagem.index.astype(str), contagem.values, color="#4C72B0", edgecolor="black")
    ax.set_title("Quantidade de Vulnerabilidades por Ano")
    ax.set_xlabel("Ano")
    ax.set_ylabel("Quantidade")
    ax.grid(axis="y", linestyle="--", alpha=0.5)

    salvar(fig, "vulnerabilidades_por_ano.png")


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("[INFO] Carregando dataset...")
    df = load_dataset()
    print(f"[INFO] Total de registros: {len(df)}")

    df = normalizar_colunas_texto(df)

    plot_cvss_hist(df)
    plot_severity(df)
    plot_attack_vector(df)
    plot_automatable(df)

    # extras
    plot_privileges_required(df)
    plot_por_ano(df)

    print("\n[OK] Todos os gráficos foram gerados em ../resultados/")


if __name__ == "__main__":
    main()