# ❓ FAQ: Banco de Dados e GitHub Actions

## 🚫 Por que o GitHub Actions não pode acessar meu banco local?

### Explicação Técnica:

```
┌─────────────────────────────────────────────┐
│         GITHUB ACTIONS RUNNER               │
│         (Servidor na nuvem da GitHub)       │
│                                             │
│   IP: 20.201.28.148 (exemplo)              │
│   Localização: Azure Data Center (US-East) │
│   Rede: Isolada                            │
└─────────────────────────────────────────────┘
              │
              │  ❌ BLOQUEADO POR:
              │  - Firewall da sua casa/empresa
              │  - NAT do seu roteador
              │  - IP privado não roteável
              │  - Segurança de rede
              │
              ▼
┌─────────────────────────────────────────────┐
│         SEU COMPUTADOR (LOCAL)              │
│                                             │
│   IP local: 192.168.1.100 (exemplo)        │
│   PostgreSQL: localhost:5432               │
│   Rede: Privada (não acessível da internet)│
└─────────────────────────────────────────────┘
```

### Por que isso é IMPOSSÍVEL?

1. **IP Privado:** Seu `localhost` (127.0.0.1) ou `192.168.x.x` não é acessível da internet
2. **Firewall:** Seu roteador bloqueia conexões externas por segurança
3. **NAT:** Seu IP público mapeia para múltiplos dispositivos na rede interna
4. **Segurança GitHub:** Runners não podem fazer conexões arbitrárias para IPs externos

---

## ✅ Soluções Disponíveis

### **Opção 1: Usar PostgreSQL Efêmero (ATUAL)**

✅ **Como funciona:**

```
┌─────────────────────────────────────────────┐
│         GITHUB ACTIONS RUNNER               │
│                                             │
│  ┌────────────────────────────────────┐   │
│  │  PostgreSQL Service Container       │   │
│  │  (Criado automaticamente)           │   │
│  │                                     │   │
│  │  - Vive apenas durante o job        │   │
│  │  - Destruído após finalização       │   │
│  │  - Dados perdidos após job          │   │
│  └────────────────────────────────────┘   │
│                                             │
│  ┌────────────────────────────────────┐   │
│  │  Exporta dados para CSV/JSON       │   │
│  │  (Antes de destruir o container)    │   │
│  └────────────────────────────────────┘   │
│                  │                          │
│                  ▼                          │
│  ┌────────────────────────────────────┐   │
│  │  GitHub Artifacts                   │   │
│  │  (Armazenamento de 90 dias)        │   │
│  └────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
              │
              │ Download manual
              ▼
┌─────────────────────────────────────────────┐
│         SEU COMPUTADOR (LOCAL)              │
│                                             │
│  python scripts/import_audit_from_github.py │
│                                             │
│  ┌────────────────────────────────────┐   │
│  │  PostgreSQL Local                   │   │
│  │  (Dados permanentes)                │   │
│  └────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

**Vantagens:**
- ✅ Funciona sem configuração externa
- ✅ Grátis (incluído no GitHub Actions)
- ✅ Você baixa artifacts e importa para demonstração

**Desvantagens:**
- ❌ Não persiste entre execuções
- ❌ Requer download manual de artifacts

---

### **Opção 2: Banco na Nuvem (PRODUÇÃO REAL)**

Se fosse um projeto **em produção real**, você usaria banco na nuvem:

```
┌─────────────────────────────────────────────┐
│         GITHUB ACTIONS RUNNER               │
│                                             │
│   Acessa via internet pública               │
└───────────────────┬─────────────────────────┘
                    │
                    │ Conexão segura (SSL)
                    ▼
┌─────────────────────────────────────────────┐
│      BANCO NA NUVEM (Acessível via IP)      │
│                                             │
│  Opções:                                    │
│  - AWS RDS (PostgreSQL)                     │
│  - Supabase (PostgreSQL grátis)            │
│  - Railway.app (PostgreSQL grátis)         │
│  - Azure Database                           │
│  - Render.com                               │
└─────────────────────────────────────────────┘
                    │
                    │ Você também acessa
                    ▼
┌─────────────────────────────────────────────┐
│         SEU COMPUTADOR (LOCAL)              │
│                                             │
│  Consulta o mesmo banco via internet        │
└─────────────────────────────────────────────┘
```

**Exemplo de configuração no GitHub Actions:**

```yaml
- name: Run Remediation Framework
  env:
    DB_HOST: my-db.supabase.co        # IP público ou domínio
    DB_PORT: 5432
    DB_NAME: remediation
    DB_USER: postgres
    DB_PASSWORD: ${{ secrets.DB_PASSWORD }}  # Secret do GitHub
  run: python framework.py
```

**Vantagens:**
- ✅ Persistência real entre execuções
- ✅ Acessível de qualquer lugar (GitHub Actions + seu PC)
- ✅ Backups automáticos

**Desvantagens:**
- ❌ Custo (mas há opções gratuitas para PoC)
- ❌ Requer configuração externa

---

## 🎯 Para seu TCC: Qual usar?

### Recomendação: **Opção 1 (Atual)**

**Por quê?**

1. ✅ **Demonstração suficiente:** Você baixa os artifacts e importa no banco local
2. ✅ **Zero custo:** Não precisa pagar nada
3. ✅ **Foco no framework:** A banca quer ver a lógica, não infraestrutura cloud
4. ✅ **Auditoria completa:** Dados ficam no seu banco local para demonstração

### Como demonstrar na apresentação:

```bash
# 1. Mostrar execução do GitHub Actions
# (navegador: Actions tab)

# 2. Baixar artifacts
# (navegador: Download "audit-logs")

# 3. Importar para banco local
python scripts/import_audit_from_github.py audit_logs/

# 4. Consultar dados
docker exec -it remediation-db psql -U postgres -d remediation

# 5. Mostrar consultas SQL
SELECT 
    package_name, 
    severity, 
    recommended_version, 
    decision_status,
    remediation_status 
FROM vulnerability_records;

# 6. Mostrar métricas
SELECT 
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE decision_status = 'APPROVED') as aprovadas,
    COUNT(*) FILTER (WHERE remediation_status = 'REMEDIATED') as corrigidas
FROM vulnerability_records;
```

**Argumento para a banca:**

> *"Em produção real, usaríamos um banco PostgreSQL na nuvem (AWS RDS, Supabase). Para esta demonstração acadêmica, optei por exportar os dados de auditoria como artifacts do GitHub Actions e importá-los localmente. Isso demonstra o conceito de **rastreabilidade e auditoria** sem incorrer custos de infraestrutura."*

---

## 🔧 Como o Banco Curado Funciona no GitHub Actions

### Fluxo completo:

```
INÍCIO DO JOB
│
├─ 1. Criar PostgreSQL Container (vazio)
│
├─ 2. Executar database/schema.sql
│      └─ Cria tabelas: pipeline_executions, vulnerability_records, homologated_versions
│
├─ 3. Executar database/seed_homologated_versions.sql
│      └─ Popula homologated_versions com versões aprovadas
│      └─ Agora o banco tem dados!
│
├─ 4. Executar framework.py
│      └─ persist_history_with_curated_db.py:
│         ├─ Consulta homologated_versions (banco temporário, mas já populado)
│         └─ Se não encontrar, consulta OSV API
│
├─ 5. Exportar dados para CSV/JSON
│      └─ Antes do banco ser destruído
│
├─ 6. Upload artifacts
│
└─ FIM DO JOB (PostgreSQL container é destruído)
```

### Exemplo de consulta no banco temporário:

```sql
-- Este código roda DENTRO do GitHub Actions

-- Passo 3: Seed populou a tabela
SELECT * FROM homologated_versions;
-- Resultado: 20+ linhas (guzzlehttp/guzzle, express, flask, etc.)

-- Passo 4: Script consulta
SELECT safe_version 
FROM homologated_versions 
WHERE package_name = 'guzzlehttp/guzzle' 
AND ecosystem = 'PHP'
ORDER BY approved_at DESC 
LIMIT 1;
-- Resultado: '6.5.8'
```

**Conclusão:** O banco curado **funciona perfeitamente** no GitHub Actions, mesmo sendo temporário, porque é **populado antes de ser usado**.

---

## 📊 Comparação: Banco Efêmero vs Nuvem

| Aspecto | Banco Efêmero (Atual) | Banco na Nuvem |
|---------|----------------------|----------------|
| **Custo** | Grátis | $0-50/mês |
| **Configuração** | Zero | Média |
| **Persistência** | Artifacts (90 dias) | Permanente |
| **Acesso local** | Import manual | Direto |
| **Adequação TCC** | ✅ Excelente | ✅ Excelente |
| **Adequação Produção** | ❌ Não recomendado | ✅ Ideal |

---

## 🎓 Resumo para o TCC

### Perguntas que a banca pode fazer:

**P: "Por que não usa um banco permanente?"**
- R: *"Para demonstração acadêmica, optei por exportar auditoria como artifacts. Em produção, usaria AWS RDS ou Supabase."*

**P: "Como garante persistência dos dados?"**
- R: *"GitHub Artifacts retém por 90 dias. Para demonstração permanente, importo no banco local via script `import_audit_from_github.py`."*

**P: "O banco curado funciona no GitHub Actions?"**
- R: *"Sim! O schema e seed são executados antes do framework. O banco é temporário, mas já vem populado com versões homologadas."*

**P: "E se o GitHub Actions não tivesse acesso ao banco?"**
- R: *"Correto, não tem acesso ao meu localhost. Por isso usamos PostgreSQL Service Container que roda no próprio runner."*

---

## 🚀 Próximos Passos

1. ✅ **Testar localmente:**
   ```bash
   # Popular banco curado
   docker exec -i remediation-db psql -U postgres -d remediation < database/seed_homologated_versions.sql
   
   # Executar framework com banco curado
   cp scripts/persist_history_with_curated_db.py scripts/persist_history.py
   python framework.py
   ```

2. ✅ **Testar no GitHub Actions:**
   ```bash
   git add .
   git commit -m "feat: adiciona banco curado de versões homologadas"
   git push origin develop
   ```

3. ✅ **Baixar artifacts e importar:**
   ```bash
   # Após job finalizar, baixar audit-logs.zip
   python scripts/import_audit_from_github.py audit_logs/
   ```

4. ✅ **Preparar demonstração para banca:**
   - Mostrar consultas SQL de auditoria
   - Explicar estratégia híbrida (curado + OSV)
   - Demonstrar rastreabilidade

---

**Dúvidas?** Releia a seção "Como o Banco Curado Funciona no GitHub Actions".

