# 🔒 Framework Autônomo de Remediação de Vulnerabilidades em Projetos Legados

> Pipeline DevSecOps que detecta, decide e corrige vulnerabilidades SCA automaticamente, com auditoria persistente no Supabase e menor impacto em projetos legados.

[![Trivy](https://img.shields.io/badge/SCA-Trivy-blue)](https://trivy.dev)
[![OSV](https://img.shields.io/badge/Database-OSV%20API-red)](https://osv.dev)
[![Supabase](https://img.shields.io/badge/DB-Supabase%20PostgreSQL-3ECF8E?logo=supabase)](https://supabase.com)
[![Multi-Language](https://img.shields.io/badge/Support-PHP%20%7C%20Node%20%7C%20Python-green)]()

---

## Sobre o Projeto

Framework desenvolvido como **Trabalho de Conclusão de Curso (TCC)** em Segurança Cibernética. Implementa remediação autônoma de vulnerabilidades em projetos legados multi-linguagem, com foco em compatibilidade (estratégia same-major) e rastreabilidade completa.

### Problema

Projetos legados acumulam bibliotecas vulneráveis. Corrigir manualmente é lento, arriscado e difícil de auditar.

### Solução

O framework detecta, decide e corrige automaticamente — abrindo PR para revisão humana antes de chegar em produção.

---

## Fluxo Completo

```
Push em develop
      │
      ▼
┌─────────────┐
│ Trivy Scan  │  ← Detecta vulnerabilidades em qualquer linguagem
└──────┬──────┘
       │  reports/report.json
       ▼
┌──────────────────────────────────────────┐
│  framework.py (Orquestrador)             │
│                                          │
│  STAGE 1 · persist_history.py           │
│    ├── Consulta banco curado (Supabase)  │
│    ├── Fallback: OSV API (Google)        │
│    └── Salva histórico no Supabase       │
│                                          │
│  STAGE 2 · decision_engine.py           │
│    ├── CRITICAL/HIGH + versão → APPROVED │
│    ├── MEDIUM → MANUAL_REVIEW            │
│    └── LOW → IGNORE                      │
│                                          │
│  STAGE 3 · remediate_2.py               │
│    ├── Detecta ecossistema               │
│    ├── composer / npm / pip              │
│    └── Salva previous_version (rollback) │
└──────────────────────────────────────────┘
       │
       ▼
┌─────────────────────┐
│  PR Automático      │  ← develop → homolog (sem aprovação)
│  fix/auto-remediation│
└──────────┬──────────┘
           │  Merge em homolog
           ▼
┌─────────────────────┐
│  Re-scan Trivy      │  ← homolog-security-gate.yml
│  exit-code: 1       │  ← Bloqueia se vuln persistir
└─────────────────────┘
           │  Sucesso
           ▼
    Status → SUCCESS
    no Supabase
```

---

## Análise Comparativa com Soluções de Mercado

### Tabela Comparativa: Estado da Arte em SCA

| Ferramenta | Implantação | Licença | Fonte CVEs | Linguagens | Estratégia Versioning | Banco Homologado | Decisão Automática | Validação Pós-Fix | Rollback Registrado | Auditoria Persistente | Rastreabilidade | Re-scan Pós-Merge | PR Automático | Security Gate | Custo/ano |
|------------|-------------|---------|------------|------------|----------------------|------------------|--------------------|-------------------|---------------------|-----------------------|-----------------|-------------------|---------------|---------------|-----------|
| **Este Framework** | Self-hosted (Actions) | MIT | Trivy + OSV API | PHP, Node, Python | **Same-major (legado)** | **Sim (Supabase curado)** | **Sim (severity-based)** | **Sim (re-scan Trivy)** | **Sim (previous_version)** | **Supabase (permanente)** | **Completa (por execução)** | **Sim** | Sim | Sim (exit-code 1) | **$0** |
| **Dependabot** | SaaS (GitHub) | Proprietário | GitHub Advisory | 20+ | Latest stable | Não | Não | Não | Não | Não persistente | Limitada | Não | Sim | Não | $0 |
| **Snyk** | SaaS/On-prem | Freemium | Snyk Intel DB | 30+ | Latest stable | Não | Parcial | Opcional | Não | SaaS (limitado) | Dashboard (pago) | Não | Sim | Configurável | ~$12.000 |
| **Renovate** | Self-hosted | AGPL | Múltiplas fontes | 40+ | Configurável | Não | Sim (regras) | Não | Não | Logs em arquivo | Limitada | Não | Sim | Não | $0 |
| **OWASP DC** | Self-hosted | Apache 2.0 | NVD + NIST | 10+ | N/A | Não | Não | N/A | N/A | Não | Não | Não | Não | Não | $0 |

> **Nota:** Dados baseados nas documentações oficiais e publicações acadêmicas sobre ferramentas SCA (Software Composition Analysis). Acesso em julho de 2026.

---

## Diferenciais da Solução

### 1. Estratégia Same-Major para Projetos Legados

Diferente de Dependabot e Snyk que recomendam a versão mais recente disponível, este framework prioriza **a menor versão que corrige a vulnerabilidade dentro da mesma série major**. Isso reduz o risco de breaking changes em sistemas legados que não podem ser refatorados rapidamente.

```
Guzzle 6.3.0 (5 CVEs HIGH)
  Dependabot → 7.8.1  (breaking changes, requer PHP 7.2.5+)
  Este framework → 6.5.8  (mesma série, zero breaking changes)
```

### 2. Banco de Versões Homologadas (Curado pela Equipe)

Nenhuma das soluções de mercado permite que a equipe de segurança **pré-aprove versões específicas** com registro de quem aprovou, quando e por quê. Este framework implementa uma tabela `homologated_versions` consultada **antes** da OSV API, garantindo que apenas versões já testadas no ambiente da organização sejam aplicadas.

```
Fluxo de consulta:
1. Banco curado (Supabase) → versão aprovada pela equipe
2. OSV API (Google)        → fallback se não encontrado
```

### 3. Auditoria Persistente com Histórico por Data

Enquanto Dependabot não persiste histórico e Renovate salva apenas logs em arquivo, este framework registra **cada execução no Supabase** com:
- Timestamp de detecção, decisão e remediação
- CVE → pacote → versão instalada → versão recomendada → status
- ID do workflow run para rastreabilidade até o GitHub Actions

O histórico **nunca é sobrescrito** — cada pipeline run insere novos registros, permitindo análise de evolução temporal da postura de segurança.

### 4. Ciclo de Validação Dupla

```
Stage 2: decision_engine.py   → decide com base em severidade
Stage 3: remediate_2.py       → aplica a correção
homolog-security-gate.yml     → re-scan Trivy valida o resultado
```

Se o re-scan detectar que a vulnerabilidade persiste, o pipeline falha com `exit-code: 1`, bloqueando o merge e registrando `ROLLED_BACK` no banco. Nenhuma ferramenta de mercado na categoria gratuita implementa esse ciclo completo.

### 5. Rollback Rastreável

Antes de aplicar qualquer correção, o script salva `previous_version` no banco. Em caso de falha no re-scan, é possível identificar exatamente qual versão estava instalada antes e reverter manualmente com rastreabilidade completa.

---

## Stack

- **Python 3.10+** — framework e scripts
- **Supabase (PostgreSQL 16)** — auditoria persistente e banco curado
- **Trivy** — scanner SCA multi-linguagem
- **OSV API** (Google) — fonte de versões seguras
- **GitHub Actions** — pipeline CI/CD
- **PHP/Composer, Node.js/npm, Python/pip** — linguagens suportadas

---

## Estrutura

```
open_innovation_virtual/
│
├── framework.py                     # Orquestrador principal
├── requirements.txt                 # Dependências Python
├── .env                             # Variáveis de ambiente (não versionado)
│
├── .github/workflows/
│   ├── ai-agent-security-pipeline.yml   # Pipeline: scan → remediate → PR
│   └── homolog-security-gate.yml        # Re-scan pós-merge em homolog
│
├── database/
│   ├── schema.sql                   # Tabelas PostgreSQL (idempotente)
│   └── seed_homologated_versions.sql# Versões curadas pela equipe
│
├── scripts/
│   ├── db.py                        # Conexão centralizada (Supabase)
│   ├── context_collector.py         # Detecção de ecossistema
│   ├── persist_history.py           # Stage 1: persistência + enriquecimento
│   ├── decision_engine.py           # Stage 2: decisão automática
│   └── remediate_2.py               # Stage 3: aplicação de correções
│
├── reports/
│   └── report.json                  # Gerado pelo Trivy (não versionado)
│
└── [Ambiente de Teste PHP]
    ├── composer.json                # Libs vulneráveis (proposital)
    ├── composer.lock
    └── index.php
```

---

## Banco de Dados (Supabase)

O Supabase mantém **histórico permanente** — cada execução do pipeline cria novos registros sem sobrescrever os anteriores.

### `pipeline_executions`
Registra cada run do GitHub Actions com status e métricas.

### `vulnerability_records`
Ciclo de vida completo de cada CVE:
- `decision_status`: `PENDING → APPROVED / MANUAL_REVIEW / IGNORE`
- `remediation_status`: `OPEN → REMEDIATED / FAILED / ROLLED_BACK`
- `previous_version`: versão anterior para rollback

### `homologated_versions`
Banco curado pela equipe — consultado **antes** da OSV API. Garante que apenas versões testadas e aprovadas sejam aplicadas em projetos legados.

### Consultas de Auditoria

```sql
-- Histórico de todas as execuções
SELECT repository_name, started_at, status, vulnerabilities_found, vulnerabilities_resolved
FROM pipeline_executions
ORDER BY started_at DESC;

-- Vulnerabilidades por execução com decisão
SELECT cve_id, package_name, severity, installed_version,
       recommended_version, decision_status, remediation_status
FROM vulnerability_records
WHERE execution_id = '<uuid>';

-- Taxa de sucesso de remediações
SELECT
    COUNT(*) FILTER (WHERE remediation_status = 'REMEDIATED') AS corrigidas,
    COUNT(*) FILTER (WHERE remediation_status = 'FAILED')     AS falhas,
    COUNT(*) FILTER (WHERE remediation_status = 'ROLLED_BACK') AS rollbacks
FROM vulnerability_records
WHERE decision_status = 'APPROVED';

-- Pacotes com rollback registrado
SELECT package_name, installed_version, previous_version, updated_at
FROM vulnerability_records
WHERE remediation_status = 'ROLLED_BACK';
```

---

## Configuração

### 1. Variáveis de ambiente locais (`.env`)

Crie um arquivo `.env` na raiz do projeto (já está no `.gitignore` — nunca sobe para o repositório):

```env
DATABASE_URL=postgresql://<usuario>:<senha>@<host>:<porta>/postgres
DB_SSLMODE=require
```

Os valores reais ficam apenas no seu `.env` local e nos Secrets do GitHub.

### 2. Secret no GitHub Actions

No repositório: **Settings → Secrets and variables → Actions → New repository secret**

| Nome | Valor |
|------|-------|
| `DATABASE_URL` | Connection string do seu banco Supabase |

A connection string do Supabase está disponível em:
**Supabase Dashboard → Project → Settings → Database → Connection string → URI**

### 3. Branches necessárias

```bash
# Criar branch homolog (destino dos PRs automáticos)
git checkout -b homolog
git push origin homolog
git checkout develop
```

O pipeline cria `homolog` automaticamente se não existir.

### 4. Aplicar schema no Supabase

```bash
pip install -r requirements.txt
python - <<EOF
import sys; sys.path.insert(0, "scripts")
from db import connect_db
conn = connect_db()
conn.cursor().execute(open("database/schema.sql").read())
conn.commit()
EOF
```

---

## Execução Local

```bash
# 1. Instalar dependências
pip install -r requirements.txt

# 2. Gerar relatório Trivy
trivy fs . --format json --output reports/report.json

# 3. Executar pipeline
python framework.py
```

---

## Pipeline GitHub Actions

### Trigger
Push em `develop` ou execução manual (`workflow_dispatch`).

### Jobs

**1. `security-scan`**
Instala Trivy, executa scan e faz upload do `report.json` como artifact.

**2. `remediation`**
Conecta no Supabase, aplica schema (idempotente), popula banco curado, executa `framework.py`. Histórico preservado — cada run insere novos registros.

**3. `open-pr`**
Cria branch `fix/auto-remediation-{run_id}` e abre PR para `homolog`. A branch `homolog` é criada automaticamente se não existir.

### Workflow de Homolog (`homolog-security-gate.yml`)

Disparado quando PR é **mergeado** em `homolog`:
- Re-scan com Trivy (`exit-code: 1` — bloqueia se vulnerável)
- Sucesso → atualiza `pipeline_executions.status = 'SUCCESS'`
- Falha → registra `ROLLED_BACK` nas vulnerabilidades e falha o pipeline

---

## Ambiente de Teste PHP

O `composer.json` usa **Guzzle 6.3.0 propositalmente** — ambiente vulnerável para demonstração do TCC.

| CVE | Severidade | Corrigida em |
|-----|------------|--------------|
| CVE-2022-29248 | HIGH | 6.5.6+ |
| CVE-2022-31042 | HIGH | 6.5.7+ |
| CVE-2022-31043 | HIGH | 6.5.7+ |
| CVE-2022-31090 | HIGH | 6.5.8+ |
| CVE-2022-31091 | HIGH | 6.5.8+ |

Remediação esperada: `6.3.0 → 6.5.8` (banco curado) ou OSV API como fallback.

⚠️ Ambiente apenas para pesquisa acadêmica.

---

## Licença

[MIT](LICENSE)

---

TCC em Segurança Cibernética — Unifacens 2026
