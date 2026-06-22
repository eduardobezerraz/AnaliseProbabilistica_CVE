import os
import pandas as pd

INPUT_CSV = "../resultados/dataset.csv"
OUTPUT_TXT = "../resultados/analise_resultados.txt"


def load_dataset():
    # sep=";" porque extract_dataset.py grava o CSV nesse formato
    # (compatível com Excel em locale PT-BR)
    df = pd.read_csv(INPUT_CSV, sep=";")
    return df


def normalizar_colunas_texto(df):
    # Padroniza valores categóricos (maiúsculas, sem espaços nas bordas)
    # para evitar que "Network" e "NETWORK" sejam contados separadamente.
    colunas_categoricas = [
        "Severity",
        "Attack_Vector",
        "Attack_Complexity",
        "Privileges_Required",
        "User_Interaction",
        "Confidentiality_Impact",
        "Integrity_Impact",
        "Availability_Impact",
    ]

    for col in colunas_categoricas:
        if col in df.columns:
            df[col] = df[col].astype(str).str.strip().str.upper()
            df[col] = df[col].replace({"NAN": pd.NA, "": pd.NA})

    if "Automatable" in df.columns:
        df["Automatable"] = df["Automatable"].astype(str).str.strip().str.lower()
        df["Automatable"] = df["Automatable"].replace({"nan": pd.NA, "none": pd.NA, "": pd.NA})

    return df


def estatistica_descritiva(df, log):
    log("\n=== ESTATÍSTICA DESCRITIVA — CVSS_Score ===")

    score = df["CVSS_Score"].dropna()

    if score.empty:
        log("Nenhum CVSS_Score disponível para análise.")
        return

    log(f"N (com score válido): {len(score)}")
    log(f"Média:        {score.mean():.3f}")
    log(f"Mediana:      {score.median():.3f}")
    log(f"Desvio padrão:{score.std():.3f}")
    log(f"Mínimo:       {score.min():.3f}")
    log(f"Máximo:       {score.max():.3f}")


def distribuicao_frequencias(df, coluna, log):
    log(f"\n=== DISTRIBUIÇÃO — {coluna} ===")

    if coluna not in df.columns:
        log(f"Coluna {coluna} não encontrada.")
        return

    contagem = df[coluna].value_counts(dropna=False)
    percentual = df[coluna].value_counts(normalize=True, dropna=False) * 100

    tabela = pd.DataFrame({
        "Contagem": contagem,
        "Percentual (%)": percentual.round(2)
    })

    log(tabela.to_string())


def probabilidade_simples(df, coluna, valor, log, descricao=None):
    total = len(df)
    if total == 0:
        return 0.0

    ocorrencias = (df[coluna] == valor).sum()
    prob = ocorrencias / total

    desc = descricao or f"P({coluna} = {valor})"
    log(f"{desc}: {prob:.4f} ({ocorrencias}/{total})")

    return prob


def probabilidade_condicional(df, coluna_a, valor_a, coluna_b, valor_b, log, descricao=None):
    subset = df[df[coluna_b] == valor_b]
    total_b = len(subset)

    if total_b == 0:
        desc = descricao or f"P({coluna_a}={valor_a} | {coluna_b}={valor_b})"
        log(f"{desc}: indefinida (nenhum registro com {coluna_b}={valor_b})")
        return None

    ocorrencias = (subset[coluna_a] == valor_a).sum()
    prob = ocorrencias / total_b

    desc = descricao or f"P({coluna_a}={valor_a} | {coluna_b}={valor_b})"
    log(f"{desc}: {prob:.4f} ({ocorrencias}/{total_b})")

    return prob


def analise_probabilidades(df, log):
    log("\n=== PROBABILIDADES SIMPLES ===")

    probabilidade_simples(
        df, "Severity", "CRITICAL", log,
        descricao="P(vulnerabilidade ser CRITICAL)"
    )

    probabilidade_simples(
        df, "Attack_Vector", "NETWORK", log,
        descricao="P(Attack_Vector = NETWORK)"
    )

    probabilidade_simples(
        df, "Privileges_Required", "NONE", log,
        descricao="P(não exigir privilégios)"
    )

    probabilidade_simples(
        df, "Automatable", "yes", log,
        descricao="P(exploração automatizável)"
    )

    log("\n=== PROBABILIDADES CONDICIONAIS ===")

    probabilidade_condicional(
        df, "Severity", "CRITICAL", "Attack_Vector", "NETWORK", log,
        descricao="P(Severity=CRITICAL | Attack_Vector=NETWORK)"
    )

    probabilidade_condicional(
        df, "Attack_Vector", "NETWORK", "Severity", "CRITICAL", log,
        descricao="P(Attack_Vector=NETWORK | Severity=CRITICAL)"
    )

    probabilidade_condicional(
        df, "Privileges_Required", "NONE", "Severity", "CRITICAL", log,
        descricao="P(Privileges_Required=NONE | Severity=CRITICAL)"
    )

    probabilidade_condicional(
        df, "Automatable", "yes", "Attack_Vector", "NETWORK", log,
        descricao="P(Automatable=yes | Attack_Vector=NETWORK)"
    )


def comparacao_entre_anos(df, log):
    log("\n=== COMPARAÇÃO ENTRE ANOS (2023 vs 2026) ===")

    if "Year" not in df.columns:
        log("Coluna Year não encontrada.")
        return

    resumo = df.groupby("Year")["CVSS_Score"].agg(["count", "mean", "median", "std", "min", "max"])
    log(resumo.round(3).to_string())

    log("\nDistribuição de Severity por ano:")
    crosstab = pd.crosstab(df["Year"], df["Severity"], normalize="index") * 100
    log(crosstab.round(2).to_string())


def main():
    os.makedirs("../resultados", exist_ok=True)

    linhas_log = []

    def log(msg):
        print(msg)
        linhas_log.append(str(msg))

    log("[INFO] Carregando dataset...")
    df = load_dataset()
    log(f"[INFO] Total de registros carregados: {len(df)}")

    df = normalizar_colunas_texto(df)

    estatistica_descritiva(df, log)

    for coluna in ["Severity", "Attack_Vector", "Attack_Complexity", "Privileges_Required", "User_Interaction", "Automatable"]:
        distribuicao_frequencias(df, coluna, log)

    analise_probabilidades(df, log)

    comparacao_entre_anos(df, log)

    with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
        f.write("\n".join(linhas_log))

    log(f"\n[OK] Resultados salvos em: {OUTPUT_TXT}")


if __name__ == "__main__":
    main()