# Guia de Contribuição

Obrigado por considerar contribuir com o **SCA Auto-Patch Framework**! 🎉

Este documento fornece diretrizes para ajudar você a contribuir de forma eficaz.

---

## 📋 Índice

- [Código de Conduta](#código-de-conduta)
- [Como Posso Contribuir?](#como-posso-contribuir)
- [Processo de Desenvolvimento](#processo-de-desenvolvimento)
- [Padrões de Código](#padrões-de-código)
- [Processo de Pull Request](#processo-de-pull-request)
- [Reportando Bugs](#reportando-bugs)
- [Sugerindo Melhorias](#sugerindo-melhorias)

---

## 📜 Código de Conduta

Este projeto adere a um código de conduta baseado no [Contributor Covenant](https://www.contributor-covenant.org/).

Ao participar, você concorda em:
- Ser respeitoso e inclusivo
- Aceitar críticas construtivas
- Focar no que é melhor para a comunidade
- Demonstrar empatia com outros membros

---

## 🤝 Como Posso Contribuir?

### 🐛 Reportando Bugs

Encontrou um bug? Ajude-nos a corrigi-lo:

1. **Verifique se já foi reportado** nas [Issues](https://github.com/PriscilaPinto/open_innovation_virtual/issues)
2. **Crie uma nova issue** com:
   - Título claro e descritivo
   - Passos para reproduzir
   - Comportamento esperado vs. comportamento atual
   - Ambiente (SO, versões PHP/Python, etc.)
   - Screenshots ou logs relevantes

**Template de Bug Report:**
```markdown
## Descrição
[Descreva o bug de forma clara]

## Como Reproduzir
1. Execute comando X
2. Acesse Y
3. Observe erro Z

## Comportamento Esperado
[O que deveria acontecer]

## Comportamento Atual
[O que está acontecendo]

## Ambiente
- SO: Windows 11 / Ubuntu 22.04 / macOS 14
- PHP: 8.1.2
- Python: 3.10.5
- Composer: 2.5.8
- Trivy: 0.70.0
```

---

### 💡 Sugerindo Melhorias

Tem uma ideia para melhorar o projeto?

1. **Abra uma Discussion** em [Ideas](https://github.com/PriscilaPinto/open_innovation_virtual/discussions/categories/ideas)
2. **Descreva a melhoria:**
   - Problema que resolve
   - Solução proposta
   - Alternativas consideradas
   - Impacto esperado

---

### 🔧 Contribuindo com Código

#### Áreas que Aceitamos Contribuições

✅ **Prioridade Alta:**
- Suporte a novos gerenciadores de pacotes (npm, pip, maven)
- Testes automatizados (pytest, PHPUnit)
- Melhoria na seleção de versões
- Tratamento de edge cases

✅ **Prioridade Média:**
- Dashboard web para visualização
- Notificações (Slack, Teams, email)
- Métricas de performance
- Documentação adicional

✅ **Prioridade Baixa:**
- Refatorações cosméticas
- Otimizações de performance
- Melhorias de logging

❌ **Não Aceitamos:**
- Mudanças que quebram compatibilidade sem justificativa forte
- Remoção de funcionalidades sem alternativa
- Código sem testes ou documentação

---

## 🛠️ Processo de Desenvolvimento

### 1️⃣ Fork e Clone

```bash
# Fork o repositório via interface do GitHub

# Clone seu fork
git clone https://github.com/SEU-USUARIO/open_innovation_virtual.git
cd open_innovation_virtual

# Adicione o upstream
git remote add upstream https://github.com/PriscilaPinto/open_innovation_virtual.git
```

### 2️⃣ Crie uma Branch

```bash
# Atualize seu fork
git checkout develop
git pull upstream develop

# Crie uma branch descritiva
git checkout -b feature/suporte-npm
# ou
git checkout -b fix/corrige-parsing-versao
```

**Convenção de Nomes de Branch:**
- `feature/` - Novas funcionalidades
- `fix/` - Correções de bugs
- `docs/` - Mudanças apenas em documentação
- `refactor/` - Refatorações sem mudança de comportamento
- `test/` - Adição ou correção de testes

### 3️⃣ Desenvolva

```bash
# Configure o ambiente
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Desenvolva e teste localmente
python framework.py
```

### 4️⃣ Commit

Siga a convenção [Conventional Commits](https://www.conventionalcommits.org/):

```bash
git add .
git commit -m "feat: adiciona suporte a npm/package.json"
```

**Tipos de Commit:**
- `feat:` - Nova funcionalidade
- `fix:` - Correção de bug
- `docs:` - Mudanças em documentação
- `style:` - Formatação, pontos e vírgulas, etc.
- `refactor:` - Refatoração de código
- `test:` - Adição de testes
- `chore:` - Atualizações de build, dependências, etc.

**Exemplos:**
```bash
feat: adiciona suporte a package-lock.json do npm
fix: corrige seleção de versão quando major difere
docs: atualiza README com exemplos de npm
test: adiciona testes para parser de package.json
refactor: extrai lógica de consulta em função separada
chore: atualiza dependência packaging para 24.1
```

### 5️⃣ Push e Pull Request

```bash
git push origin feature/suporte-npm
```

Abra um Pull Request no GitHub com:
- Título claro seguindo Conventional Commits
- Descrição detalhada das mudanças
- Referências a issues relacionadas (`Closes #123`)
- Screenshots/logs se aplicável

---

## 📏 Padrões de Código

### Python

**Siga PEP 8:**
```bash
# Instale ferramentas de linting
pip install ruff black

# Formate o código
black framework.py

# Verifique linting
ruff check framework.py
```

**Boas Práticas:**
- Type hints em todas as funções
- Docstrings no formato Google Style
- Nomes de variáveis descritivos
- Máximo 100 caracteres por linha
- Imports organizados (stdlib, third-party, local)

**Exemplo:**
```python
def selecionar_versao_homologada(
    pacote: str,
    versao_instalada: str,
    versoes_corrigidas: list[str],
    versoes_packagist: list[str],
) -> str | None:
    """
    Seleciona a versão homologada ideal para remediação.

    Args:
        pacote: Nome do pacote no formato vendor/package
        versao_instalada: Versão atual instalada (semver)
        versoes_corrigidas: Lista de versões que corrigem CVEs
        versoes_packagist: Versões disponíveis no repositório

    Returns:
        Versão selecionada ou None se não encontrar candidata
    """
    # Implementação...
```

### PHP

**Siga PSR-12:**
- Indentação com 4 espaços
- Chaves de abertura na mesma linha (métodos) ou linha seguinte (classes)
- Type declarations sempre que possível

### YAML (GitHub Actions)

- Indentação com 2 espaços
- Nomes de steps descritivos
- Comentários explicando lógica complexa

---

## 🔍 Processo de Pull Request

### Checklist Antes de Enviar

- [ ] Código segue os padrões estabelecidos
- [ ] Commits seguem Conventional Commits
- [ ] Testes foram adicionados/atualizados (se aplicável)
- [ ] Documentação foi atualizada (README, CHANGELOG)
- [ ] Branch está atualizada com `develop`
- [ ] Não há conflitos de merge
- [ ] Pipeline CI passou sem erros

### Revisão

Seu PR será revisado para:
- ✅ Qualidade de código
- ✅ Cobertura de testes
- ✅ Documentação
- ✅ Compatibilidade com arquitetura existente
- ✅ Performance

Esteja aberto a feedback e iterações!

### Merge

Após aprovação:
- Squash de commits será aplicado
- Mensagem de merge seguirá Conventional Commits
- Branch será deletada automaticamente

---

## 🧪 Testes

### Testes Locais

```bash
# Execute o framework com relatório de exemplo
python framework.py

# Valide com Trivy
trivy fs . --severity CRITICAL,HIGH
```

### CI/CD

O GitHub Actions executará automaticamente:
- Linting de código
- Scan de segurança
- Validação de workflows

---

## 📚 Recursos Úteis

- [Python PEP 8](https://peps.python.org/pep-0008/)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Packagist API](https://packagist.org/apidoc)
- [Semantic Versioning](https://semver.org/)

---

## 🙋 Precisa de Ajuda?

- 💬 **Dúvidas gerais:** [Discussions](https://github.com/PriscilaPinto/open_innovation_virtual/discussions)
- 🐛 **Bugs:** [Issues](https://github.com/PriscilaPinto/open_innovation_virtual/issues)
- 📧 **Contato direto:** Via GitHub ou email do mantenedor

---

**Obrigado por contribuir! Juntos tornamos a segurança de software mais acessível. 🚀**
