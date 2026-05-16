# Autonomous Vulnerability Remediation Framework

Framework experimental para remediação autônoma de vulnerabilidades em aplicações legadas utilizando IA Generativa, SCA e DevSecOps.

---

## Objetivo

O projeto propõe uma esteira automatizada capaz de:

- detectar vulnerabilidades em bibliotecas de terceiros
- analisar relatórios SCA
- aplicar remediações automáticas
- validar correções
- executar pipelines de segurança automatizados
- abrir Pull Requests automaticamente

---

## Arquitetura

```text
Legacy PHP Application
        ↓
GitHub Actions CI/CD
        ↓
Trivy SCA Scan
        ↓
JSON Vulnerability Report
        ↓
AI Security Agent
        ↓
Automated Remediation
        ↓
SCA Revalidation
        ↓
Pull Request / Security Ticket
```

---

## Stack

- PHP 8.1
- Composer
- Python
- Trivy
- GitHub Actions
- Ubuntu 22.04
- git version 2.54.0.windows.1

---

## Dependências Vulneráveis

| Biblioteca | Versão |
|---|---|
| Guzzle | 6.3.0 |
| Monolog | 1.24.0 |

---

## Pipeline DevSecOps

O projeto utiliza GitHub Actions para automação de análise de vulnerabilidades em dependências PHP.

O pipeline executa automaticamente:

1. checkout do repositório
2. instalação das dependências PHP
3. instalação do Trivy
4. análise SCA do projeto
5. geração de relatório JSON
6. upload do relatório como artifact
7. persistência automática do relatório no repositório

Relatórios são armazenados em:

```text
reports/report.json
```

---

## Execução Local

### Instalar dependências

```bash
composer install
```

### Executar aplicação

```bash
php -S localhost:8000
```

### Executar análise SCA localmente

```bash
mkdir -p reports

trivy fs . \
  --format json \
  --output reports/report.json
```

---

## GitHub Actions

O workflow de segurança está localizado em:

```text
.github/workflows/security-scan.yml
```

O pipeline é executado automaticamente em:

- push para branch `main`
- pull requests

---

## Vulnerabilidades Detectadas

O Trivy identifica vulnerabilidades conhecidas presentes nas dependências vulneráveis do ambiente legado.

Exemplos identificados:

- CVE-2022-29248
- CVE-2022-31042
- CVE-2022-31043
- CVE-2022-31090
- CVE-2022-31091

---

## Roadmap

- [x] Ambiente legado vulnerável
- [x] Pipeline DevSecOps
- [x] Trivy SCA
- [x] Relatórios automatizados
- [x] Execução diária via cron
- [ ] Agente IA
- [ ] Remediação automática
- [ ] Virtual patching
- [ ] Revalidação automática
- [ ] Auto Pull Request

---

## Contexto Acadêmico

Projeto desenvolvido como Trabalho de Conclusão de Curso (TCC) em Segurança Cibernética.

### Tema

> Remediação Autônoma de Vulnerabilidades em Cadeia de Suprimentos via IA Generativa

---

## Aviso

Projeto exclusivamente acadêmico e laboratorial.

As bibliotecas utilizadas neste ambiente são vulneráveis propositalmente para fins de pesquisa, demonstração de SCA e testes de remediação automatizada.
