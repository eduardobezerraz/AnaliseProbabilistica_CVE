# Análise Probabilística de Vulnerabilidades CVE (2020–2026)

## Descrição

Este projeto tem como objetivo realizar uma análise estatística e probabilística de vulnerabilidades registradas no banco de dados CVE (Common Vulnerabilities and Exposures), utilizando registros oficiais do projeto CVE List V5.

A pesquisa concentra-se nos anos de 2020 a 2026, analisando os primeiros identificadores de cada ano (`CVE-YYYY-0xxx`) e extraindo métricas relacionadas à severidade, superfície de ataque, requisitos de exploração e impacto das vulnerabilidades.

---

## Objetivos

* Construir um dataset estruturado a partir dos registros CVE.
* Extrair variáveis relevantes para análise estatística.
* Investigar padrões de vulnerabilidades ao longo do tempo.
* Avaliar características associadas à explorabilidade e ao impacto.
* Aplicar métodos probabilísticos e estatísticos em dados reais de segurança cibernética.

---

## Fonte dos Dados

Os dados utilizados são provenientes do repositório oficial do CVE Program:

* https://github.com/CVEProject/cvelistV5

Foram considerados os registros dos anos:

* 2020
* 2021
* 2022
* 2023
* 2024
* 2025
* 2026

Para cada ano, são analisados os primeiros CVEs do intervalo:

```text
CVE-YYYY-0001
até
CVE-YYYY-0999
```

---

## Variáveis Extraídas

### Severidade

| Variável   | Tipo     |
| ---------- | -------- |
| CVSS Score | Numérica |

### Explorabilidade

| Variável            | Tipo       |
| ------------------- | ---------- |
| Attack Vector       | Categórica |
| Attack Complexity   | Categórica |
| Privileges Required | Categórica |
| User Interaction    | Categórica |

### Impacto

| Variável               | Tipo    |
| ---------------------- | ------- |
| Confidentiality Impact | Ordinal |
| Integrity Impact       | Ordinal |
| Availability Impact    | Ordinal |

### Contexto

| Variável       | Tipo       |
| -------------- | ---------- |
| Vendor         | Categórica |
| Product        | Categórica |
| Published Date | Temporal   |

### Informações Operacionais

| Variável     | Tipo       |
| ------------ | ---------- |
| Exploitation | Categórica |
| Automatable  | Binária    |

---

## Estrutura do Projeto

```text
AnaliseProbabilistica_CVE/
│
├── cves/
│   ├── 2010/
│   ├── 2011/
│   ├── 2012/
│   ├── .
│   ├── .
│   └── 2026/
│
├── scripts/
│   ├── extract_dataset.py
│   ├── statistical_analysis.py
│   └── plots.py
│
├── resultados/
│   ├── imagens/
│   └── tabelas/
│
├── requeriments.txt
└── README.md
```

---

## Metodologia

1. Coleta dos registros CVE.
2. Extração automática dos campos de interesse.
3. Limpeza e padronização dos dados.
4. Construção do dataset tabular.
5. Análise estatística exploratória.
6. Aplicação de métodos probabilísticos.
7. Visualização dos resultados.

---

## Possíveis Análises

### Estatística Descritiva

* Média, mediana e desvio padrão do CVSS Score.
* Distribuição de severidade das vulnerabilidades.
* Frequência de vetores de ataque.
* Frequência de privilégios requeridos.

### Análise Temporal

* Evolução anual dos CVEs.
* Tendências de severidade ao longo do tempo.
* Mudanças nos vetores de ataque predominantes.

### Comparação entre Produtos e Fornecedores

* Produtos com maior incidência de vulnerabilidades.
* Fornecedores mais representados na amostra.
* Distribuição de severidade por fornecedor.

### Análise de Explorabilidade

* Relação entre Attack Vector e CVSS Score.
* Relação entre Privileges Required e severidade.
* Frequência de vulnerabilidades exploráveis sem autenticação.

### Modelagem Probabilística

* Distribuições de probabilidade para CVSS Score.
* Estimativas de ocorrência de vulnerabilidades por categoria.
* Análise de dependência entre variáveis.

---

## Tecnologias Utilizadas

* Python
* Pandas
* NumPy
* Matplotlib

---

## Instalação

Clone este repositório:

```bash
git clone https://github.com/eduardobezerraz/AnaliseProbabilistica_CVE.git
```

Instale as dependências:

```bash
pip install -r requirements.txt
```

---

## 📥 Obtenção dos Dados Brutos (Reprodutibilidade)

Os dados utilizados neste projeto não estão incluídos no repositório devido ao seu grande volume.  
Para reproduzir a análise, o colaborador deve obter os registros oficiais do CVE List V5.

---

### 🔹 Passo 1 — Clone com sparse checkout

```bash
git clone --depth 1 --filter=blob:none --sparse https://github.com/CVEProject/cvelistV5.git
cd cvelistV5
```

### 🔹 Passo 2 — Selecionar apenas os anos necessários (2010–2016)
```bash
git sparse-checkout init --cone

git sparse-checkout set \
cves/2010 \
cves/2011 \
cves/2012 \
cves/2013 \
cves/2014 \
cves/2015 \
cves/2016
```

#### Estrutura esperada: 
cvelistV5/
└── cves/
    ├── 2010/
    ├── 2011/
    ├── 2012/
    ├── 2013/
    ├── 2014/
    ├── 2015/
    └── 2016/

---

## Execução

Execute o script de extração:

```bash
python scripts/extract_dataset.py
```

O resultado será um dataset estruturado contendo as variáveis extraídas dos registros CVE selecionados.

---

## Questões de Pesquisa

Este projeto busca investigar questões como:

* Existe correlação entre CVSS Score e Attack Vector?
* Vulnerabilidades que não exigem privilégios prévios tendem a apresentar maior severidade?
* Determinados produtos concentram vulnerabilidades mais críticas?
* Há mudanças significativas no perfil das vulnerabilidades entre 2020 e 2026?
* A distribuição das vulnerabilidades segue padrões estatísticos conhecidos?

---

## Licença

Este projeto possui finalidade acadêmica, educacional e de pesquisa.

Os dados originais pertencem ao programa CVE e aos respectivos fornecedores responsáveis pelos registros de vulnerabilidades.
