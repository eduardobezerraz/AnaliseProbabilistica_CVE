# 📊 Análise Probabilística de Vulnerabilidades CVE (2010–2026)

## Descrição

Este projeto tem como objetivo realizar uma análise aprofundada das vulnerabilidades catalogadas no banco de dados **CVE (Common Vulnerabilities and Exposures)**, utilizando os registros oficiais do projeto **CVE List V5**.

A pesquisa concentra-se nos anos de **2010 a 2026**, analisando os primeiros identificadores de cada ano (`CVE-YYYY-0xxx`) e extraindo métricas relacionadas à severidade, superfície de ataque, requisitos de exploração e impacto das vulnerabilidades.

Os dados são obtidos diretamente do repositório oficial do CVE Program e processados com Python para gerar um dataset tabular pronto para análises estatísticas e modelagem probabilística.

## Objetivos

* Construir um dataset estruturado a partir dos registros CVE.
* Extrair variáveis relevantes para análise estatística.
* Investigar padrões de vulnerabilidades ao longo do tempo.
* Avaliar características associadas à explorabilidade e ao impacto.
* Aplicar métodos probabilísticos e estatísticos em dados reais de segurança cibernética.

## Fonte dos Dados

Os dados utilizados são provenientes do repositório oficial do CVE Program:

* https://github.com/CVEProject/cvelistV5

Foram considerados os registros dos anos:

* 2010
* 2011
* 2012
* .
* .
* .
* 2024
* 2025
* 2026

Para cada ano, são analisados os primeiros CVEs do intervalo:

```text
CVE-YYYY-0001
até
CVE-YYYY-0999
```

## 📋 Variáveis Extraídas

<table>
  <tr>
    <th style="background:#dc3545;color:white;">Categoria</th>
    <th style="background:#dc3545;color:white;">Variável</th>
    <th style="background:#dc3545;color:white;">Tipo</th>
  </tr>
  <tr style="background:#fff3f3;">
    <td rowspan="1"><b>🚨 Severidade</b></td>
    <td>CVSS Score</td>
    <td><code>🔢 Numérica</code></td>
  </tr>
  <tr>
    <th style="background:#007bff;color:white;" rowspan="4">🧩 Explorabilidade</th>
    <td>Attack Vector</td>
    <td><code>🎯 Categórica</code></td>
  </tr>
  <tr style="background:#f0f8ff;">
    <td>Attack Complexity</td>
    <td><code>🎯 Categórica</code></td>
  </tr>
  <tr>
    <td>Privileges Required</td>
    <td><code>🎯 Categórica</code></td>
  </tr>
  <tr style="background:#f0f8ff;">
    <td>User Interaction</td>
    <td><code>🎯 Categórica</code></td>
  </tr>
  <tr>
    <th style="background:#ffc107;color:black;" rowspan="3">💥 Impacto</th>
    <td>Confidentiality Impact</td>
    <td><code>🔒 Ordinal</code></td>
  </tr>
  <tr style="background:#fffde7;">
    <td>Integrity Impact</td>
    <td><code>🔒 Ordinal</code></td>
  </tr>
  <tr>
    <td>Availability Impact</td>
    <td><code>🔒 Ordinal</code></td>
  </tr>
  <tr>
    <th style="background:#28a745;color:white;" rowspan="3">🏷️ Contexto</th>
    <td>Vendor</td>
    <td><code>🎯 Categórica</code></td>
  </tr>
  <tr style="background:#f0fff0;">
    <td>Product</td>
    <td><code>🎯 Categórica</code></td>
  </tr>
  <tr>
    <td>Published Date</td>
    <td><code>⌚ Temporal</code></td>
  </tr>
  <tr>
    <th style="background:#6f42c1;color:white;" rowspan="2">⚙️ Operacionais</th>
    <td>Exploitation</td>
    <td><code>🎯 Categórica</code></td>
  </tr>
  <tr style="background:#f8f0ff;">
    <td>Automatable</td>
    <td><code>0️⃣ Binária</code></td>
  </tr>
</table>



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



## Metodologia

1. Coleta dos registros CVE.
2. Extração automática dos campos de interesse.
3. Limpeza e padronização dos dados.
4. Construção do dataset tabular.
5. Análise estatística exploratória.
6. Aplicação de métodos probabilísticos.
7. Visualização dos resultados.



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



## 📥 Obtenção dos Dados Brutos (Reprodutibilidade)

Os dados utilizados neste projeto não estão incluídos no repositório devido ao seu grande volume.  
Para reproduzir a análise, o colaborador deve obter os registros oficiais do CVE List V5.



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
```text
cvelistV5/
└── cves/
    ├── 2010/
    ├── 2011/
    ├── 2012/
    ├── .
    ├── .
    ├── 2025/
    └── 2026/
```


## Execução

Execute o script de extração:

```bash
python scripts/extract_dataset.py
```

O resultado será um dataset estruturado contendo as variáveis extraídas dos registros CVE selecionados.



## Questões de Pesquisa

Este projeto busca investigar questões como:

* Existe correlação entre CVSS Score e Attack Vector?
* Vulnerabilidades que não exigem privilégios prévios tendem a apresentar maior severidade?
* Determinados produtos concentram vulnerabilidades mais críticas?
* Há mudanças significativas no perfil das vulnerabilidades entre 2010 e 2026?
* A distribuição das vulnerabilidades segue padrões estatísticos conhecidos?



## Licença

Este projeto possui finalidade acadêmica, educacional e de pesquisa.

Os dados originais pertencem ao programa CVE e aos respectivos fornecedores responsáveis pelos registros de vulnerabilidades.
