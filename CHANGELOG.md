# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/lang/pt-BR/).

## [2.0.0] - 2026-06-28

### 🚀 Adicionado
- Framework Python completo de remediação automática (`framework.py`)
- Consulta dinâmica ao Packagist para versões homologadas
- Estratégia inteligente de seleção de versão (mesma série major)
- Atualização automática de `composer.json` e `composer.lock`
- Re-scan de validação pós-remediação
- Pull Request automatizado para branch `homolog`
- Workflow `ai-agent-security-pipeline.yml` com 3 stages
- Security gate `homolog-security-gate.yml` pós-merge
- Arquivo `.env.example` para documentação de variáveis
- Documentação completa no README com diagramas e exemplos

### ♻️ Modificado
- **BREAKING CHANGE**: Removida dependência de IA/LLM (OpenAI/Gemini)
- Abordagem mudou de "Virtual Patching" para "SCA Auto-Patch"
- `requirements.txt` simplificado (apenas `packaging`)
- README totalmente reescrito com arquitetura, fluxos e exemplos
- `.gitignore` corrigido (removia a si mesmo)

### ❌ Depreciado
- Scripts na pasta `/scripts` (remediate.py, ai_analyzer.py, etc.)
- Uso de banco PostgreSQL para decisões de remediação
- Variável de ambiente `GEMINI_API_KEY`

### 🐛 Corrigido
- Inconsistências entre código ativo e scripts antigos
- Dependências Python incorretas em `requirements.txt`
- Workflow referenciando variáveis não utilizadas

---

## [1.0.0] - 2026-05-17

### 🚀 Adicionado
- Ambiente PHP legado com Guzzle 6.3.0 vulnerável
- Pipeline DevSecOps com Trivy SCA
- Geração automática de `reports/report.json`
- GitHub Actions workflow para scan de segurança
- Persistência de relatórios no repositório
- Docker Compose para PostgreSQL
- Schema SQL para tracking de vulnerabilidades
- Scripts Python de PoC para análise com IA

### 📝 Documentação
- README inicial com objetivos do projeto
- Documentação de stack tecnológica
- Instruções de execução local

---

## Legenda

- `🚀 Adicionado` para novas funcionalidades
- `♻️ Modificado` para mudanças em funcionalidades existentes
- `❌ Depreciado` para funcionalidades que serão removidas
- `🗑️ Removido` para funcionalidades removidas
- `🐛 Corrigido` para correções de bugs
- `🔒 Segurança` para correções de vulnerabilidades
