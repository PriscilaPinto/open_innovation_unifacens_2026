# Autonomous Vulnerability Remediation Framework

Framework experimental para remediação autônoma de vulnerabilidades em aplicações legadas utilizando IA Generativa, SCA e DevSecOps.

## Objetivo

O projeto propõe uma esteira automatizada capaz de:

- detectar vulnerabilidades em bibliotecas de terceiros
- analisar relatórios SCA
- aplicar remediações automáticas
- validar correções
- abrir Pull Requests automaticamente

---

## Arquitetura

```text
Legacy Application
        ↓
Dependency-Check
        ↓
JSON Report
        ↓
AI Agent
        ↓
Automated Remediation
        ↓
SCA Revalidation
        ↓
PR / Ticket
```

---

## Stack

- PHP 8.1
- Composer
- Python
- Java 17
- OWASP Dependency-Check
- GitHub Actions
- Ubuntu 22.04

---

## Dependências Vulneráveis

| Biblioteca | Versão |
|---|---|
| Guzzle | 6.3.0 |
| Monolog | 1.24.0 |

---

## Execução

### Instalar dependências

```bash
composer install
```

### Executar aplicação

```bash
php -S localhost:8000
```

### Executar SCA

```bash
./bin/dependency-check.sh \
--scan ~/legacy-php-app \
--format ALL \
--out reports
```

---

## Roadmap

- [x] Ambiente legado
- [x] SCA funcional
- [ ] Agente IA
- [ ] Remediação automática
- [ ] Revalidação
- [ ] GitHub Actions
- [ ] Auto PR

---

## Contexto Acadêmico

Projeto desenvolvido como Trabalho de Conclusão de Curso (TCC) em Segurança Cibernética.

Tema:
> Remediação Autônoma de Vulnerabilidades em Cadeia de Suprimentos via IA Generativa

---

## ⚠️ Aviso

Projeto exclusivamente acadêmico/laboratorial. AS bibliotecas deste projeto sao vulneraveis propositalmente.
