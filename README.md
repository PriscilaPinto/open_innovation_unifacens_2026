# Autonomous Vulnerability Remediation Framework

Framework experimental para remediação autônoma de vulnerabilidades em aplicações legadas utilizando IA Generativa, SCA e DevSecOps.

## Objetivo

O projeto propõe uma esteira automatizada capaz de:

- detectar vulnerabilidades em bibliotecas de terceiros
- analisar relatórios SCA
- aplicar remediações automáticas
- validar correções
- executar pipelines de segurança automatizados
- abrir Pull Requests automaticamente

## Arquitetura

Legacy PHP Application → GitHub Actions CI/CD → Trivy SCA Scan → JSON Vulnerability Report → AI Security Agent → Automated Remediation → SCA Revalidation → Pull Request / Security Ticket

## Stack

- PHP 8.1
- Composer
- Python
- Trivy
- GitHub Actions
- Ubuntu 22.04
- git version 2.54.0.windows.1

## Dependências Vulneráveis

| Biblioteca | Versão |
|------------|--------|
| Guzzle     | 6.3.0  |
| Monolog    | 1.24.0 |

## Pipeline DevSecOps

O pipeline automatiza análise de vulnerabilidades em dependências PHP usando GitHub Actions.

Executa:

- checkout do repositório
- instalação das dependências PHP
- instalação do Trivy
- análise SCA
- geração de relatório JSON
- upload como artifact
- persistência no repositório

Relatório salvo em: reports/report.json

## Execução Local

composer install

php -S localhost:8000

mkdir -p reports
trivy fs . --format json --output reports/report.json

## GitHub Actions

Workflow: .github/workflows/security-scan.yml

Executado em:
- push em develop
- pull requests
- workflow_dispatch
- cron (03:00 UTC)

## Vulnerabilidades Detectadas

- CVE-2022-29248
- CVE-2022-31042
- CVE-2022-31043
- CVE-2022-31090
- CVE-2022-31091

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

## Contexto Acadêmico

TCC em Segurança Cibernética.

Tema: Remediação Autônoma de Vulnerabilidades em Cadeia de Suprimentos via IA Generativa

## Aviso

Projeto exclusivamente acadêmico e laboratorial. As vulnerabilidades são intencionais para pesquisa e testes.
