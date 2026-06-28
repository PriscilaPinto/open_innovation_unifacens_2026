# 🔒 Framework Autônomo de Remediação de Vulnerabilidades em Projetos Legados

> Sistema inteligente de remediação automática de vulnerabilidades SCA (Software Composition Analysis) para projetos legados multi-linguagem, com foco em menor impacto e quebra zero.

[![Trivy](https://img.shields.io/badge/SCA-Trivy-blue)](https://trivy.dev)
[![OSV](https://img.shields.io/badge/Database-OSV%20API-red)](https://osv.dev)
[![PostgreSQL](https://img.shields.io/badge/DB-PostgreSQL%2016-336791?logo=postgresql)](https://www.postgresql.org/)
[![Multi-Language](https://img.shields.io/badge/Support-PHP%20%7C%20Node%20%7C%20Python-green)]()

---

## 📋 Sobre o Projeto

Framework desenvolvido como **Trabalho de Conclusão de Curso (TCC)** em Segurança Cibernética que implementa um pipeline DevSecOps completo para **remediação autônoma de vulnerabilidades em projetos legados**.

### 🎯 Problema

Projetos legados frequentemente utilizam bibliotecas desatualizadas com vulnerabilidades conhecidas. Atualizar manualmente é:
- ⏰ **Demorado** - Análise CVE por CVE
- 🔥 **Arriscado** - Quebra de compatibilidade em produção
- 🤔 **Complexo** - Escolher versão de menor impacto

### ✨ Solução

Framework que **automatiza todo o processo**:
1. 🔍 **Detecta** vulnerabilidades via Trivy SCA
2. 💾 **Consulta** base de versões homologadas (OSV API)
3. 🤖 **Decide** automaticamente baseado em severidade
4. 🔧 **Aplica** correções de forma agnóstica (PHP, Node.js, Python)
5. ✅ **Valida** com re-scan antes de produção
6. 🚀 **Abre PR** automaticamente para revisão

### 🌟 Diferenciais

- ✅ **Multi-linguagem** - PHP/Composer, Node.js/npm, Python/pip
- ✅ **Agnóstico** - Detecta ecossistema automaticamente
- ✅ **Inteligente** - Consulta OSV API para menor impacto
- ✅ **Seguro** - Validação dupla (decisão + re-scan)
- ✅ **Legado-friendly** - Foco em compatibilidade
- ✅ **Auditável** - Histórico completo para compliance

---

### 🌟 Diferenciais

- ✅ **Multi-linguagem** - PHP/Composer, Node.js/npm, Python/pip
- ✅ **Agnóstico** - Detecta ecossistema automaticamente
- ✅ **Inteligente** - Consulta OSV API para menor impacto
- ✅ **Seguro** - Validação dupla (decisão + re-scan)
- ✅ **Legado-friendly** - Foco em compatibilidade
- ✅ **Auditável** - Histórico completo para compliance

---

## 📊 Análise Comparativa com Soluções de Mercado

### Tabela Comparativa: Estado da Arte

| Dimensão | Critério | Este Framework | Dependabot | Snyk | Renovate | OWASP DC |
|----------|----------|----------------|------------|------|----------|----------|
| **Arquitetura** | Tipo de implantação | Self-hosted (Docker) | SaaS (GitHub) | SaaS/On-premise | Self-hosted | Self-hosted |
| | Licenciamento | MIT (Open-source) | Proprietário | Freemium/Comercial | AGPL (Open-source) | Apache 2.0 |
| | Modelo de dados | Relacional (PostgreSQL) | Não exposto | Proprietário | Logs locais | Arquivo local |
| **Detecção** | Fonte de CVEs | Trivy + OSV API | GitHub Advisory | Snyk Intel DB | Datasources configuráveis | NVD + NIST |
| | Cobertura de linguagens | 3 (PHP, Node.js, Python) | 20+ | 30+ | 40+ | 10+ |
| | Granularidade | Dependências diretas | Diretas + transitivas | Diretas + transitivas | Configurável | Diretas + transitivas |
| **Remediação** | Estratégia de versioning | **Menor impacto (same-major)** | Latest stable | Latest stable | Configurável | N/A (apenas detecção) |
| | Base de recomendação | **OSV API (Google)** | GitHub metadata | Snyk proprietary | Release notes | N/A |
| | Decisão automática | **Sim (severity-based)** | Não | Parcial (policy-based) | Sim (regras) | Não |
| | Validação pós-fix | **Sim (re-scan Trivy)** | Não | Opcional (CI checks) | Não | N/A |
| **Auditoria** | Persistência histórica | **PostgreSQL (completo)** | Não persistente | SaaS (limitado) | Logs arquivos | Não |
| | Rastreabilidade | Sim (pipeline_executions) | Limitada (GitHub API) | Sim (dashboard) | Limitada | Não |
| | Métricas temporais | Sim (queries SQL) | Não | Sim (dashboard) | Não | Não |
| | Compliance ready | Sim (LGPD, SOC2) | Não | Sim (pago) | Não | Não |
| **DevSecOps** | Integração CI/CD | GitHub Actions | GitHub nativo | Multi-plataforma | Multi-plataforma | Manual |
| | Abertura automática PR | Sim | Sim | Sim | Sim | Não |
| | Security gate | Sim (exit-code 1) | Não | Configurável | Não | Não |
| **Econômico** | Custo (10 devs/ano) | $0 | $0 | ~$12.000 | $0 | $0 |
| | TCO infraestrutura | Baixo (Docker) | Zero | Variável | Baixo | Baixo |

**Nota:** Tabela baseada em análise comparativa das documentações oficiais e papers acadêmicos sobre ferramentas de SCA (Software Composition Analysis).

---

## 🏗️ Arquitetura

```
┌──────────────────────────────────────────────────────────────┐
│                    GITHUB ACTIONS WORKFLOW                    │
│                                                               │
│  Trigger: Push em develop                                    │
└──────────────────────────────────────────────────────────────┘
                            ↓
                    ┌──────────────┐
                    │  Trivy Scan  │
                    │ (Multi-lang) │
                    └──────────────┘
                            ↓
                  reports/report.json
                            ↓
┌──────────────────────────────────────────────────────────────┐
│              FRAMEWORK.PY (Orquestrador)                      │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  STAGE 1: persist_history.py                                 │
│  ├─ Lê relatório Trivy                                       │
│  ├─ Para cada vulnerabilidade:                               │
│  │  ├─ Consulta OSV API (versão homologada)                 │
│  │  └─ Salva no PostgreSQL                                   │
│  └─ Retorna: execution_id                                    │
│                                                               │
│  STAGE 2: decision_engine.py                                 │
│  ├─ Busca vulnerabilidades OPEN no banco                     │
│  ├─ Aplica regras de decisão:                                │
│  │  ├─ CRITICAL/HIGH + versão recomendada → APPROVED        │
│  │  ├─ MEDIUM → MANUAL_REVIEW                               │
│  │  └─ LOW → IGNORE                                          │
│  └─ Atualiza decision_status no banco                        │
│                                                               │
│  STAGE 3: remediate_2.py                                     │
│  ├─ Detecta ecossistema (context_collector.py):             │
│  │  ├─ composer.json → PHP/Composer                         │
│  │  ├─ package.json → Node.js/npm                           │
│  │  └─ requirements.txt → Python/pip                        │
│  ├─ Busca vulnerabilidades APPROVED no banco                 │
│  ├─ Executa comando apropriado:                              │
│  │  ├─ composer require pacote:versao                       │
│  │  ├─ npm install pacote@versao                            │
│  │  └─ pip install pacote==versao                           │
│  └─ Atualiza remediation_status (REMEDIATED/FAILED)         │
│                                                               │
└──────────────────────────────────────────────────────────────┘
                            ↓
                ┌────────────────────┐
                │  Trivy Re-scan     │
                │  (Validação final) │
                └────────────────────┘
                            ↓
                ┌────────────────────┐
                │  Pull Request      │
                │  develop → homolog │
                └────────────────────┘
                            ↓
                ┌────────────────────┐
                │  Security Gate     │
                │  (exit-code: 1)    │
                └────────────────────┘
```

---

## 🛠️ Stack Tecnológica

### Backend & Database
- **Python** 3.10+ - Framework e scripts
- **PostgreSQL** 16 - Base de versões homologadas + **Auditoria completa**
- **Docker Compose** - Infraestrutura

### Análise de Segurança
- **Trivy** 0.70.0 - Scanner SCA multi-linguagem
- **OSV API** - Open Source Vulnerabilities Database (Google)

### DevOps
- **GitHub Actions** - Pipeline CI/CD
- **Docker** - Containerização

### Linguagens Suportadas
| Linguagem | Gerenciador | Manifest | Lockfile | Status |
|-----------|-------------|----------|----------|--------|
| PHP | Composer | composer.json | composer.lock | ✅ Testado |
| Node.js | npm | package.json | package-lock.json | ✅ Suportado |
| Python | pip | requirements.txt | requirements.txt | ✅ Suportado |

---

## 📂 Estrutura do Projeto

```
open_innovation_virtual/
│
├── framework.py                      # ⭐ Orquestrador principal
├── .env                              # Configuração do banco
├── docker-compose.yml                # PostgreSQL container
├── requirements.txt                  # Dependências Python
│
├── .github/workflows/
│   ├── ai-agent-security-pipeline.yml    # Pipeline principal
│   └── homolog-security-gate.yml         # Gate de validação
│
├── database/
│   ├── schema.sql                    # Schema PostgreSQL
│   └── seed_homologated_versions.sql # Versões homologadas (curadas)
│
├── docs/
│   ├── ESTRATEGIAS_HOMOLOGACAO.md    # Explica OSV vs Banco Curado
│   └── FAQ_BANCO_DADOS.md            # FAQ sobre banco e GitHub Actions
│
├── reports/
│   └── report.json                   # Gerado pelo Trivy (GitHub Actions)
│
├── scripts/
│   ├── persist_history.py                    # STAGE 1: Persistência + OSV API
│   ├── persist_history_with_curated_db.py    # STAGE 1 ALT: Banco Curado + OSV
│   ├── decision_engine.py                    # STAGE 2: Decisão automática
│   ├── remediate_2.py                        # STAGE 3: Aplicação de correções
│   ├── context_collector.py                  # Detecção de ecossistema
│   ├── import_audit_from_github.py           # Importa artifacts para banco local
│   ├── remediate.py                          # Versão simplificada (legado)
│   └── ai_analyzer.py                        # PoC experimental com IA
│
└── [Ambiente de Teste PHP]
    ├── composer.json                 # Libs vulneráveis (proposital)
    ├── composer.lock
    └── index.php                     # App de teste
```

---

## 🚀 Quick Start

### Pré-requisitos

- Docker & Docker Compose
- Python 3.10+
- PHP 8.1+ e Composer (para teste PHP)
- Trivy (para scan local)

### 1. Clone o Repositório

```bash
git clone https://github.com/PriscilaPinto/open_innovation_virtual.git
cd open_innovation_virtual
```

### 2. Configure o Ambiente

O arquivo `.env` já está configurado:
```env
DB_HOST=localhost
DB_PORT=5432
DB_NAME=remediation
DB_USER=postgres
DB_PASSWORD=postgres
```

### 3. Suba a Infraestrutura

```bash
# Iniciar PostgreSQL
docker-compose up -d

# Criar schema do banco
docker exec -i remediation-db psql -U postgres -d remediation < database/schema.sql

# Verificar
docker exec -it remediation-db psql -U postgres -d remediation -c "\dt"
```

Deve listar 3 tabelas:
- `pipeline_executions`
- `vulnerability_records`
- `pull_requests`

### 4. Instale Dependências Python

```bash
pip install -r requirements.txt
```

Dependências instaladas:
- `psycopg2-binary` - Conexão PostgreSQL
- `requests` - Consulta OSV API
- `python-dotenv` - Variáveis de ambiente

### 5. Execute o Framework Localmente

```bash
# (Opcional) Gerar relatório Trivy localmente
trivy fs . --format json --output reports/report.json

# Executar pipeline completo
python framework.py
```

---

## 📊 Funcionamento Detalhado

### STAGE 1: Persistência e Enriquecimento (`persist_history.py`)

**Objetivo:** Salvar vulnerabilidades e consultar versões homologadas

**Fluxo:**
1. Lê `reports/report.json` gerado pelo Trivy
2. Para cada vulnerabilidade encontrada:
   - Extrai: CVE ID, package name, severity, installed version, fixed version
   - **Consulta OSV API:** `POST https://api.osv.dev/v1/query`
     ```json
     {
       "package": {"name": "guzzlehttp/guzzle", "ecosystem": "Packagist"},
       "version": "6.3.0"
     }
     ```
   - Extrai `recommended_version` da resposta (menor impacto)
   - Salva no PostgreSQL (`vulnerability_records`)
3. Atualiza métricas em `pipeline_executions`

**Saída:**
```
Execution saved: a1b2c3d4-...
Vulnerabilities saved: 5
```

---

### STAGE 2: Engine de Decisão (`decision_engine.py`)

**Objetivo:** Decidir quais vulnerabilidades remediar automaticamente

**Regras de Decisão:**

| Condição | Decisão | Ação |
|----------|---------|------|
| `severity IN ('CRITICAL', 'HIGH')` E `recommended_version IS NOT NULL` | `APPROVED` | Remediação automática |
| `severity = 'MEDIUM'` | `MANUAL_REVIEW` | Requer aprovação humana |
| `severity = 'LOW'` | `IGNORE` | Ignorado (baixo risco) |
| `recommended_version IS NULL` | `MANUAL_REVIEW` | OSV não tem recomendação |

**Saída:**
```
Vulnerability decision: APPROVED
Vulnerability decision: APPROVED
...
Approved: 5
Manual Review: 0
Ignored: 0
```

---

### STAGE 3: Aplicação de Remediações (`remediate_2.py`)

**Objetivo:** Aplicar correções no projeto de forma agnóstica

**Fluxo:**

1. **Detecta Ecossistema** (`context_collector.py`):
   ```python
   if os.path.exists("composer.json"):
       ecosystem = "php"
       package_manager = "composer"
   elif os.path.exists("package.json"):
       ecosystem = "node"
       package_manager = "npm"
   elif os.path.exists("requirements.txt"):
       ecosystem = "python"
       package_manager = "pip"
   ```

2. **Busca Vulnerabilidades Aprovadas:**
   ```sql
   SELECT id, package_name, recommended_version
   FROM vulnerability_records
   WHERE decision_status = 'APPROVED'
   AND remediation_status = 'OPEN'
   ```

3. **Executa Comando Apropriado:**
   ```bash
   # PHP
   composer require guzzlehttp/guzzle:6.5.8
   
   # Node.js
   npm install express@4.18.2
   
   # Python
   pip install flask==2.3.0
   ```

4. **Atualiza Status:**
   - Sucesso → `remediation_status = 'REMEDIATED'`
   - Falha → `remediation_status = 'FAILED'`

**Saída:**
```
Ecosystem detected: php
Package manager detected: composer
composer found: /usr/local/bin/composer

Remediating guzzlehttp/guzzle -> 6.5.8
Executing: composer require guzzlehttp/guzzle:6.5.8
Remediation successful

Remediated: 1
Failed: 0
```

---

## 🔍 Ambiente de Teste

O projeto inclui um ambiente PHP **propositalmente vulnerável** para demonstração:

### Bibliotecas Vulneráveis (composer.json)

```json
{
  "require": {
    "guzzlehttp/guzzle": "6.3.0",    // 5 CVEs HIGH
    "monolog/monolog": "1.24.0"      // Sem vulnerabilidades
  }
}
```

### Vulnerabilidades Conhecidas

| CVE | Severidade | Descrição | Versão Corrigida |
|-----|------------|-----------|------------------|
| CVE-2022-29248 | HIGH | Cookie middleware vulnerability | 6.5.6+ |
| CVE-2022-31042 | HIGH | Cookie header leak on redirect | 6.5.7+ |
| CVE-2022-31043 | HIGH | Authorization header leak | 6.5.7+ |
| CVE-2022-31090 | HIGH | CURLOPT_HTTPAUTH leak | 6.5.8+ |
| CVE-2022-31091 | HIGH | Auth/Cookie leak on port change | 6.5.8+ |

**Remediação Esperada:** `guzzlehttp/guzzle: 6.3.0 → 6.5.8`

⚠️ **AVISO:** Este ambiente é **apenas para pesquisa acadêmica**. Não use em produção!

---

## 💾 Banco de Dados PostgreSQL

### Propósito: Auditoria e Rastreabilidade

O PostgreSQL não é apenas uma base de versões - ele **registra todo o histórico** de execuções do pipeline para:

✅ **Auditoria Completa**
- Quando cada vulnerabilidade foi detectada
- Qual decisão foi tomada (aprovada/ignorada/revisão manual)
- Se a remediação foi bem-sucedida ou falhou
- Quem/quando executou o pipeline

✅ **Métricas e Relatórios**
- Quantas vulnerabilidades foram encontradas por execução
- Taxa de sucesso de remediações
- Percentual de redução de vulnerabilidades
- Histórico de evolução da segurança do projeto

✅ **Rastreabilidade**
- Ligação entre execução do pipeline e Pull Request
- Versionamento de decisões
- Logs de falhas para troubleshooting

### Duas Estratégias de Homologação

O framework suporta **duas estratégias** para consultar versões seguras:

1. **OSV API (Padrão):** Consulta apenas Google OSV API
2. **Banco Curado + OSV (Híbrido):** Prioriza versões homologadas pela equipe, fallback para OSV

📖 **Leia mais:** [docs/ESTRATEGIAS_HOMOLOGACAO.md](docs/ESTRATEGIAS_HOMOLOGACAO.md)

### PostgreSQL no GitHub Actions

⚠️ **Importante:** O banco no GitHub Actions é **efêmero** (recriado a cada execução).

**Como funciona:**
1. Banco temporário criado durante job
2. Populado com schema + versões homologadas
3. Framework processa vulnerabilidades
4. **Dados exportados** para CSV/JSON (GitHub Artifacts)
5. Banco destruído após job

**Para auditoria local:**
```bash
# Baixar artifacts do GitHub Actions
# Importar para banco local
python scripts/import_audit_from_github.py audit_logs/
```

❓ **Dúvidas sobre banco de dados?** Leia: [docs/FAQ_BANCO_DADOS.md](docs/FAQ_BANCO_DADOS.md)

### Tabela: `pipeline_executions`

Registra cada execução do framework:

```sql
CREATE TABLE pipeline_executions (
    id UUID PRIMARY KEY,
    repository_name TEXT,
    workflow_run_id TEXT,           -- ID do GitHub Actions
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    status TEXT,                    -- SUCCESS, FAILED
    vulnerabilities_found INTEGER,
    vulnerabilities_resolved INTEGER,
    reduction_percentage NUMERIC(5,2)
);
```

### Tabela: `vulnerability_records`

Registra cada vulnerabilidade e seu ciclo de vida completo:

```sql
CREATE TABLE vulnerability_records (
    id UUID PRIMARY KEY,
    execution_id UUID,              -- FK para pipeline_executions
    cve_id TEXT,                    -- CVE-2022-29248
    package_name TEXT,              -- guzzlehttp/guzzle
    severity TEXT,                  -- HIGH, CRITICAL, etc.
    installed_version TEXT,         -- 6.3.0
    fixed_version TEXT,             -- 6.5.6, 7.4.3 (do Trivy)
    recommended_version TEXT,       -- 6.5.8 (da OSV API)
    osv_reference TEXT,             -- OSV ID
    decision_status TEXT,           -- APPROVED, MANUAL_REVIEW, IGNORE
    remediation_status TEXT,        -- OPEN, REMEDIATED, FAILED
    created_at TIMESTAMP,           -- Quando foi detectada
    updated_at TIMESTAMP            -- Última modificação
);
```

### Tabela: `pull_requests`

Rastreia PRs gerados automaticamente:

```sql
CREATE TABLE pull_requests (
    id UUID PRIMARY KEY,
    execution_id UUID,              -- FK para pipeline_executions
    pr_number INTEGER,              -- #123
    pr_url TEXT,
    approval_status TEXT,           -- PENDING, APPROVED, REJECTED
    created_at TIMESTAMP
);
```

### Tabela: `homologated_versions` (Opcional - Banco Curado)

Armazena versões **aprovadas manualmente pela equipe** de segurança:

```sql
CREATE TABLE homologated_versions (
    id UUID PRIMARY KEY,
    package_name TEXT NOT NULL,     -- guzzlehttp/guzzle
    ecosystem TEXT NOT NULL,        -- PHP, Node.js, Python
    safe_version TEXT NOT NULL,     -- 6.5.8
    approved_by TEXT,               -- Nome do aprovador
    approved_at TIMESTAMP,          -- Quando foi aprovado
    notes TEXT,                     -- Motivo, testes realizados
    UNIQUE(package_name, ecosystem, safe_version)
);
```

**Exemplo de dados:**

```sql
-- Ver versões homologadas
SELECT * FROM homologated_versions WHERE package_name = 'guzzlehttp/guzzle';

-- Resultado:
-- | package_name        | safe_version | approved_by    | notes
-- |---------------------|--------------|----------------|-------
-- | guzzlehttp/guzzle   | 6.5.8        | Security Team  | Última versão 6.x, sem breaking changes
-- | guzzlehttp/guzzle   | 7.4.5        | Security Team  | Versão 7.x, requer PHP 7.2+
```

**Popular banco curado:**

```bash
# Local
docker exec -i remediation-db psql -U postgres -d remediation < database/seed_homologated_versions.sql

# Verificar
docker exec -it remediation-db psql -U postgres -d remediation -c "SELECT COUNT(*) FROM homologated_versions;"
```

### Consultas Úteis para Auditoria

```bash
# Entrar no PostgreSQL
docker exec -it remediation-db psql -U postgres -d remediation

# Ver todas as vulnerabilidades detectadas
SELECT package_name, severity, recommended_version, decision_status, remediation_status 
FROM vulnerability_records;

# Ver apenas aprovadas
SELECT * FROM vulnerability_records WHERE decision_status = 'APPROVED';

# Ver remediadas com sucesso
SELECT * FROM vulnerability_records WHERE remediation_status = 'REMEDIATED';

# Histórico de execuções do pipeline
SELECT id, repository_name, started_at, vulnerabilities_found, vulnerabilities_resolved, 
       reduction_percentage
FROM pipeline_executions
ORDER BY started_at DESC;

# Eficácia das remediações (taxa de sucesso)
SELECT 
    COUNT(*) FILTER (WHERE remediation_status = 'REMEDIATED') as sucesso,
    COUNT(*) FILTER (WHERE remediation_status = 'FAILED') as falhas,
    ROUND(
        COUNT(*) FILTER (WHERE remediation_status = 'REMEDIATED')::numeric / 
        COUNT(*)::numeric * 100, 2
    ) as taxa_sucesso_pct
FROM vulnerability_records
WHERE decision_status = 'APPROVED';

# Vulnerabilidades por severidade
SELECT severity, COUNT(*), 
       COUNT(*) FILTER (WHERE remediation_status = 'REMEDIATED') as corrigidas
FROM vulnerability_records 
GROUP BY severity
ORDER BY 
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
    END;

# Evolução temporal (últimas 30 execuções)
SELECT 
    DATE(started_at) as data,
    SUM(vulnerabilities_found) as total_vulnerabilidades,
    SUM(vulnerabilities_resolved) as total_corrigidas,
    AVG(reduction_percentage) as reducao_media_pct
FROM pipeline_executions
WHERE started_at >= NOW() - INTERVAL '30 days'
GROUP BY DATE(started_at)
ORDER BY data DESC;
```

---

## ⚙️ Pipeline GitHub Actions

### Workflow: `ai-agent-security-pipeline.yml`

**Trigger:**
- Push em `develop`
- Pull Requests
- Manual (`workflow_dispatch`)

**Jobs:**

#### 1. `security-scan`
- Instala Trivy
- Executa: `trivy fs . --format json --output reports/report.json`
- Upload do report como artifact

#### 2. `ai-remediation`
- **PostgreSQL Service Container** (efêmero)
  - Criado automaticamente a cada execução
  - Usado apenas durante o job
  - **Destruído após o job** (não persiste entre execuções)
- Download do report
- Setup Python + dependências
- Cria schema do banco
- **Executa:** `python framework.py`
- **Exporta auditoria:** CSV/JSON dos dados do banco
- Upload de arquivos modificados + logs de auditoria

#### 3. `security-validation`
- Re-scan com Trivy (validação)
- Limpa cache do Trivy
- **Cria Pull Request** para `homolog`

---

### 📊 Persistência de Dados de Auditoria

**Importante:** O PostgreSQL no GitHub Actions é **efêmero** (recriado a cada execução).

**Solução implementada:**

1. **Durante o job:** Banco PostgreSQL temporário para processamento
2. **Antes de finalizar:** Export de dados em CSV/JSON como **GitHub Artifacts**
3. **Retenção:** 90 dias no GitHub (configurável)

**Arquivos exportados:**
```
audit_logs/
├── pipeline_executions_20260628_143022.csv
├── vulnerability_records_20260628_143022.csv
└── metrics_20260628_143022.json
```

**Para auditoria permanente em produção:**
- Opção A: Usar banco externo (AWS RDS, Supabase, Railway)
- Opção B: Commitar `audit_logs/` no repositório (via PR automático)
- Opção C: Enviar para S3/Azure Blob Storage

### Workflow: `homolog-security-gate.yml`

**Trigger:** Merge de PR em `homolog`

**Ação:**
- Executa Trivy final
- **`exit-code: 1`** - Bloqueia se vulnerabilidades HIGH/CRITICAL persistirem

---

## 🧪 Testes Locais

### Teste Completo

```bash
# 1. Subir infraestrutura
docker-compose up -d
docker exec -i remediation-db psql -U postgres -d remediation < database/schema.sql

# 2. Instalar dependências
pip install -r requirements.txt

# 3. Gerar relatório Trivy
trivy fs . --format json --output reports/report.json

# 4. Executar framework
python framework.py

# 5. Verificar resultado
git status  # composer.json modificado
git diff composer.json  # Ver versão atualizada
```

### Validação

```bash
# Re-scan após remediação
trivy fs . --severity HIGH,CRITICAL

# Consultar banco
docker exec -it remediation-db psql -U postgres -d remediation -c \
  "SELECT package_name, installed_version, recommended_version, remediation_status FROM vulnerability_records;"
```

---

## 🎓 Contexto Acadêmico

### TCC em Segurança Cibernética

**Tema:** Remediação Autônoma de Vulnerabilidades em Projetos Legados via SCA e Base de Versões Homologadas

**Objetivos:**
1. Reduzir MTTR (Mean Time To Remediation) de vulnerabilidades
2. Minimizar breaking changes em código legado
3. Automatizar decisões de segurança baseadas em severidade
4. Validar eficácia de remediação multi-linguagem

**Contribuições:**
- Framework agnóstico (PHP, Node.js, Python)
- Integração OSV API para menor impacto
- Pipeline DevSecOps completo
- Validação dupla (decisão + re-scan)
- **Sistema de auditoria e rastreabilidade completo**

---

## 🔐 Considerações de Segurança

### Ambiente Seguro
- Banco PostgreSQL isolado (Docker)
- Credenciais via variáveis de ambiente
- Workflow com permissões mínimas

### Validação Multi-Camada
1. **Decisão Automática** - Regras baseadas em severidade
2. **Re-scan Pós-Remediação** - Trivy valida correção
3. **Security Gate** - Bloqueia merge se vulnerável
4. **Revisão Humana** - PR para aprovação final

### Limitações Conhecidas
- ⚠️ OSV API pode não ter todas as versões
- ⚠️ Foca apenas em dependências diretas
- ⚠️ Não executa testes da aplicação automaticamente

---

## 🤝 Contribuindo

Veja [CONTRIBUTING.md](CONTRIBUTING.md) para guidelines de contribuição.

---

## 📄 Licença

Este projeto é licenciado sob [MIT License](LICENSE).

---

## 👥 Autora

**Priscila Pinto**  
📧 41971828+PriscilaPinto@users.noreply.github.com  
🔗 [@PriscilaPinto](https://github.com/PriscilaPinto)

---

## 🙏 Agradecimentos

- [Aqua Security](https://www.aquasec.com/) - Trivy SCA Scanner
- [Google OSV](https://osv.dev/) - Open Source Vulnerabilities Database
- Comunidade open-source de segurança

---

<div align="center">

**Desenvolvido para tornar projetos legados mais seguros através de automação inteligente** 🔒

⭐ Se este projeto foi útil para sua pesquisa ou trabalho, considere dar uma estrela!

</div>
