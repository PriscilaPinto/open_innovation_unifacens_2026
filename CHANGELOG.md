# Changelog

Formato: [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/) | Versionamento: [SemVer](https://semver.org/)

---

## [3.0.0] - 2026-07-11

### Adicionado
- Integração com **Supabase** como banco persistente entre execuções de pipeline
- Coluna `previous_version` em `vulnerability_records` para suporte a rollback
- `scripts/db.py` — módulo centralizado de conexão (suporta `DATABASE_URL` ou variáveis individuais)
- Criação automática da branch `homolog` no job `open-pr` se não existir
- PR com ID único por run (`fix/auto-remediation-{run_id}`) evitando conflitos
- Rollback registrado no banco quando re-scan em homolog falha
- `ON CONFLICT DO NOTHING` no seed — seguro para executar múltiplas vezes
- Schema com `CREATE TABLE IF NOT EXISTS` — idempotente

### Modificado
- `persist_history.py` unifica as versões anterior e curada (banco curado + OSV API como fallback)
- `decision_engine.py` agrupa por pacote com `DISTINCT ON` — evita remediação duplicada
- `remediate_2.py` salva `previous_version` antes de atualizar
- `framework.py` simplificado e seleciona script por `USE_CURATED_DB` removido (agora sempre usa banco curado)
- Workflows reescritos com `DATABASE_URL` secret apontando para Supabase
- `requirements.txt` com versões fixas (`==`) para builds reproduzíveis

### Removido
- `scripts/ai_analyzer.py` — PoC não integrado ao pipeline
- `scripts/ai_remediation.py` — script legado não utilizado
- `scripts/import_audit_from_github.py` — não necessário com Supabase persistente
- `scripts/persist_history_with_curated_db.py` — unificado em `persist_history.py`
- `REVIEW.md` — documento temporário de revisão
- `docs/FAQ_BANCO_DADOS.md`, `docs/ESTRATEGIAS_HOMOLOGACAO.md` — documentação temporária
- `docker-compose.yml` — substituído por Supabase

---

## [2.0.0] - 2026-06-28

### Adicionado
- Framework Python de orquestração (`framework.py`)
- Pipeline GitHub Actions com 3 stages (scan → remediate → PR)
- PostgreSQL Service Container no GitHub Actions
- Exportação de auditoria como GitHub Artifacts (CSV/JSON)
- `scripts/persist_history_with_curated_db.py` com estratégia híbrida
- `database/seed_homologated_versions.sql` com versões PHP, Node.js e Python
- Tabela `homologated_versions` no schema

### Corrigido
- `SyntaxError` em `remediate_2.py` (backticks de markdown no final do arquivo)
- SQL inválido no seed (múltiplos `INSERT INTO` separados)
- Checkout incorreto da branch `homolog` no Stage 3

---

## [1.0.0] - 2026-05-17

### Adicionado
- Ambiente PHP legado com Guzzle 6.3.0 (vulnerável propositalmente)
- Pipeline DevSecOps com Trivy SCA
- Schema PostgreSQL para tracking de vulnerabilidades
- Scripts Python de PoC com IA (Gemini/OpenRouter)
- Docker Compose para PostgreSQL local
