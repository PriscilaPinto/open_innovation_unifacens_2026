# 🔒 Política de Segurança

## Versões Suportadas

Use esta seção para saber quais versões do projeto estão atualmente recebendo atualizações de segurança.

| Versão | Suportada          |
| ------ | ------------------ |
| 2.0.x  | :white_check_mark: |
| 1.0.x  | :x:                |

---

## ⚠️ Aviso Importante

**Este projeto contém dependências propositalmente vulneráveis para fins educacionais e de pesquisa.**

As seguintes bibliotecas são mantidas em versões antigas **intencionalmente**:
- `guzzlehttp/guzzle: 6.3.0` (com 5 CVEs HIGH conhecidas)

**❌ NÃO USE ESTE CÓDIGO EM PRODUÇÃO SEM ATUALIZAR AS DEPENDÊNCIAS.**

---

## 🐛 Reportando uma Vulnerabilidade

Se você descobrir uma vulnerabilidade de segurança neste projeto, por favor **NÃO** abra uma issue pública.

### Processo de Reporte Seguro

1. **Envie um email privado para:**
   - 📧 41971828+PriscilaPinto@users.noreply.github.com
   - Assunto: `[SECURITY] Vulnerabilidade em SCA Auto-Patch`

2. **Inclua as seguintes informações:**
   - Descrição detalhada da vulnerabilidade
   - Passos para reproduzir
   - Impacto potencial
   - Versão afetada
   - Sugestão de correção (se tiver)

3. **Você pode esperar:**
   - Confirmação de recebimento em até **48 horas**
   - Avaliação inicial em até **5 dias úteis**
   - Plano de correção em até **14 dias** (se confirmado)

### O Que Acontece Depois

1. **Triagem (0-5 dias):**
   - Validamos a vulnerabilidade
   - Avaliamos severidade (CVSS)
   - Definimos prioridade

2. **Desenvolvimento (5-14 dias):**
   - Criamos patch de segurança
   - Testamos solução
   - Preparamos release notes

3. **Divulgação (14-21 dias):**
   - Publicamos patch
   - Creditamos descobridor (se desejar)
   - Atualizamos SECURITY.md

---

## 🎯 Escopo de Segurança

### ✅ Incluso no Escopo

Reportes aceitos para:
- **framework.py**: Lógica de remediação
- **Workflows GitHub Actions**: Injeção de comandos, vazamento de secrets
- **Dependências Python**: Vulnerabilidades em `packaging`
- **Documentação**: Instruções inseguras

### ❌ Fora do Escopo

NÃO reportar:
- Vulnerabilidades nas **bibliotecas PHP intencionalmente vulneráveis** (Guzzle 6.3.0, etc.)
  - Estas são o **objeto de estudo** do projeto
- Problemas em `scripts/` obsoletos (marcados como DEPRECATED)
- Vulnerabilidades em PostgreSQL Docker (componente opcional não-crítico)

---

## 🏆 Hall da Fama de Segurança

Agradecemos aos seguintes pesquisadores que reportaram vulnerabilidades responsavelmente:

_(Em breve - seja o primeiro!)_

---

## 🔐 Boas Práticas de Segurança

### Para Usuários

Se você está usando este framework:

1. **Nunca commit `.env`** com credenciais reais
2. **Use secrets do GitHub Actions** para variáveis sensíveis
3. **Revise PRs automáticos** antes de merge
4. **Execute em ambiente isolado** (containers, VMs)
5. **Atualize dependências regularmente:**
   ```bash
   pip install --upgrade packaging
   ```

### Para Contribuidores

Ao contribuir com código:

1. **Nunca inclua:**
   - API keys, tokens, senhas
   - Dados pessoais ou identificáveis
   - Informações proprietárias

2. **Sempre valide:**
   - Inputs de usuário
   - Respostas de APIs externas
   - Comandos de shell

3. **Use:**
   - Type hints para prevenir bugs
   - Try/except para tratamento de erros
   - Timeout em operações de rede

---

## 📚 Recursos de Segurança

### Ferramentas Recomendadas

- **Trivy**: Scanner SCA (usado pelo projeto)
- **Bandit**: Análise de código Python
- **Safety**: Verificação de dependências Python
- **pip-audit**: Auditoria de pacotes PyPI

### Como Escanear o Projeto

```bash
# Scan completo com Trivy
trivy fs . --severity CRITICAL,HIGH

# Scan apenas Python
trivy fs . --security-checks vuln --scanners vuln

# Análise estática Python
pip install bandit
bandit -r framework.py
```

---

## 📞 Contato

- 🐛 **Bugs gerais:** [GitHub Issues](https://github.com/PriscilaPinto/open_innovation_virtual/issues)
- 🔒 **Vulnerabilidades:** Email privado (acima)
- 💬 **Discussões:** [GitHub Discussions](https://github.com/PriscilaPinto/open_innovation_virtual/discussions)

---

## 📜 Divulgação Coordenada

Aderimos aos princípios de **Responsible Disclosure**:

- ✅ Damos crédito aos descobridores (com permissão)
- ✅ Patches antes de divulgação pública
- ✅ Transparência após correção
- ✅ Comunicação proativa com usuários

---

## 🆕 Histórico de Segurança

### 2026-06-28 - v2.0.0
- ✅ Removida dependência de IA (eliminando riscos de prompt injection)
- ✅ Implementado timeout em subprocess calls
- ✅ Validação de versões semver
- ✅ Sanitização de inputs de APIs externas

### 2026-05-17 - v1.0.0
- 🎉 Release inicial
- ⚠️ Continha bibliotecas intencionalmente vulneráveis (ambiente de pesquisa)

---

**Última atualização:** 2026-06-28  
**Próxima revisão:** 2026-12-28
