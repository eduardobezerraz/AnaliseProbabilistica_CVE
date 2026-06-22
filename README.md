# 📊 Análise Probabilística de Vulnerabilidades CVE (2023–2026)

## Descrição

Este projeto tem como objetivo realizar uma análise probabilística e estatística de vulnerabilidades catalogadas no banco de dados **CVE (Common Vulnerabilities and Exposures)**, utilizando registros oficiais do projeto **CVE List V5**.

A análise considera uma amostra composta pelos primeiros registros de cada ano, abrangendo o período de **2023 a 2026**. Para cada ano, são analisadas as vulnerabilidades do intervalo **CVE-YYYY-0001 até CVE-YYYY-0999**, totalizando até aproximadamente **4.000 registros**.

Os dados são processados com Python para gerar um dataset estruturado, permitindo a aplicação de técnicas de estatística descritiva e probabilidade em um conjunto de dados reais da área de segurança da informação.

---

# 🎯 Objetivos

- Construir um dataset estruturado a partir dos registros CVE.
- Extrair informações relevantes sobre severidade e exploração.
- Realizar análises estatísticas descritivas.
- Aplicar conceitos básicos de probabilidade em dados reais.
- Produzir visualizações para interpretação dos resultados.

---

# 📂 Fonte dos Dados

Os registros utilizados são provenientes do repositório oficial do CVE Program:

https://github.com/CVEProject/cvelistV5

Foram considerados apenas os anos:

- 2023
- 2024
- 2025
- 2026

Para cada ano são analisados apenas os registros:

```text
CVE-YYYY-0001
até
CVE-YYYY-0999
```


# 📋 Variáveis Extraídas

| Categoria       | Variável               | Tipo       |
| --------------- | ---------------------- | ---------- |
| Identificação   | CVE ID                 | Texto      |
| Identificação   | Ano                    | Numérica   |
| Severidade      | CVSS Score             | Numérica   |
| Severidade      | Severity               | Categórica |
| Explorabilidade | Attack Vector          | Categórica |
| Explorabilidade | Attack Complexity      | Categórica |
| Explorabilidade | Privileges Required    | Categórica |
| Explorabilidade | User Interaction       | Categórica |
| Impacto         | Confidentiality Impact | Categórica |
| Impacto         | Integrity Impact       | Categórica |
| Impacto         | Availability Impact    | Categórica |
| Operacionais    | Automatable            | Binária    |



# Estrutura do Projeto

```text
AnaliseProbabilistica_CVE/
│
├── cves/
│   ├── 2023/
│   ├── 2024/
│   ├── 2025/
│   └── 2026/
│
├── scripts/
│   ├── extract_dataset.py
│   ├── analysis.py
│   └── plots.py
│
├── resultados/
│   ├── dataset.csv
│   ├── dataset.xlsx
│   ├── cvss_hist.png
│   ├── severity.png
│   ├── attack_vector.png
│   └── automatable.png
│
├── requirements.txt
└── README.md
```



# Metodologia

1. Obtenção dos registros CVE.
2. Extração automática das variáveis de interesse.
3. Organização dos dados em um dataset tabular.
4. Limpeza e padronização dos dados.
5. Aplicação de estatística descritiva.
6. Cálculo de probabilidades simples e condicionais.
7. Geração de gráficos para visualização dos resultados.



# Análises Realizadas

## Estatística Descritiva

- Média do CVSS Score
- Mediana
- Desvio padrão
- Valores mínimo e máximo
- Distribuição das severidades

## Distribuições

- Frequência de Attack Vector
- Frequência de Attack Complexity
- Frequência de Privileges Required
- Frequência de User Interaction

## Probabilidade

Exemplos de probabilidades calculadas:

- Probabilidade de uma vulnerabilidade ser Critical.
- Probabilidade de possuir Attack Vector = Network.
- Probabilidade de não exigir privilégios.
- Probabilidade de exploração automatizável.
- Probabilidade condicional entre severidade e vetor de ataque.



# Visualizações

O projeto gera gráficos como:

- Histograma do CVSS Score
- Distribuição das severidades
- Distribuição dos vetores de ataque
- Distribuição dos privilégios requeridos
- Distribuição de vulnerabilidades por ano



# Tecnologias Utilizadas

- Python
- Pandas
- Matplotlib
- OpenPyXL



# Instalação

Clone o repositório:

```bash
git clone https://github.com/eduardobezerraz/AnaliseProbabilistica_CVE.git
```

Instale as dependências:

```bash
pip install -r requirements.txt
```



# Obtenção dos Dados

Os arquivos JSON não são distribuídos neste repositório devido ao seu volume.

Para reproduzir a análise:

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git

cd cvelistV5

git sparse-checkout init --cone

git sparse-checkout set \
cves/2023 \
cves/2024 \
cves/2025 \
cves/2026
```

A estrutura esperada é:

```text
cvelistV5/
└── cves/
    ├── 2023/
    ├── 2024/
    ├── 2025/
    └── 2026/
```

Em seguida, copie a pasta `cves` para a raiz deste projeto.



# Execução

Gerar o dataset:

```bash
python scripts/extract_dataset.py
```

Realizar a análise estatística:

```bash
python scripts/analysis.py
```

Gerar os gráficos:

```bash
python scripts/plots.py
```

Todos os resultados serão armazenados na pasta `resultados/`.



# Questões de Pesquisa

Este trabalho busca responder questões como:

- Qual a severidade média das vulnerabilidades analisadas?
- Qual o vetor de ataque mais frequente?
- Vulnerabilidades críticas costumam exigir privilégios?
- Qual a probabilidade de uma vulnerabilidade ser explorável remotamente?
- Existe diferença no perfil das vulnerabilidades entre 2023 e 2026?



# Resultados Esperados

Ao final da execução do projeto, espera-se obter:

- Um dataset consolidado contendo aproximadamente **4.000 registros de vulnerabilidades** (CVE-2023-0001 a CVE-2026-0999).
- Arquivos de saída nos formatos **CSV** e **Excel**, prontos para análises posteriores.
- Estatísticas descritivas das variáveis extraídas, como média, mediana, desvio padrão e distribuição de frequências.
- Estimativas de probabilidades simples e condicionais relacionadas às características das vulnerabilidades.
- Gráficos que representem a distribuição da severidade, vetores de ataque, privilégios requeridos e evolução das vulnerabilidades por ano.

Os resultados obtidos servirão como exemplo da aplicação de técnicas de estatística descritiva e probabilidade em um conjunto de dados real da área de Segurança da Informação.



# Licença

Projeto desenvolvido para fins acadêmicos.

Os registros CVE pertencem ao **CVE Program** e aos respectivos fornecedores responsáveis pela divulgação das vulnerabilidades.
