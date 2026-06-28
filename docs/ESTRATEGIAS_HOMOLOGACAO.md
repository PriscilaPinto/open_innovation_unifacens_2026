# 🔍 Estratégias de Homologação de Versões

Este documento explica as **duas estratégias** disponíveis no framework para consultar versões seguras de pacotes.

---

## 📊 Comparação das Estratégias

| Aspecto | Estratégia 1: OSV API | Estratégia 2: Banco Curado + OSV |
|---------|----------------------|----------------------------------|
| **Script** | `persist_history.py` | `persist_history_with_curated_db.py` |
| **Fonte primária** | Google OSV API | Banco PostgreSQL (homologated_versions) |
| **Fonte secundária** | N/A | Google OSV API (fallback) |
| **Vantagem** | Sempre atualizado | Controle total da equipe |
| **Desvantagem** | Sem controle de aprovação | Requer manutenção manual |
| **Uso recomendado** | PoC, prototipação | Produção, TCC (demonstra governança) |

---

## 🟢 Estratégia 1: OSV API (Padrão)

### Como funciona:

```
┌──────────────────┐
│ Trivy detecta    │
│ vulnerabilidade  │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────┐
│ persist_history.py       │
│                          │
│ 1. Query OSV API         │
│ 2. Extrai versão fixa    │
│ 3. Salva no PostgreSQL   │
└──────────────────────────┘
```

### Código:

```python
# scripts/persist_history.py
osv_data = query_osv(package_name, installed_version)

if osv_data:
    recommended_version = osv_data['recommended_version']
```

### Vantagens:

✅ Simples de implementar  
✅ Base mantida pelo Google  
✅ Sempre atualizada  
✅ Multi-linguagem (PHP, Node.js, Python, Go, Rust, etc.)

### Desvantagens:

❌ Sem controle sobre versões recomendadas  
❌ OSV pode recomendar breaking changes  
❌ Não demonstra processo de homologação/governança

---

## 🔵 Estratégia 2: Banco Curado + OSV (Híbrido)

### Como funciona:

```
┌──────────────────┐
│ Trivy detecta    │
│ vulnerabilidade  │
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────┐
│ persist_history_with_curated_db.py   │
│                                      │
│ 1. Consulta banco curado             │
│    ├─ Se encontrar → USA (prioriza)  │
│    └─ Se não encontrar → OSV API     │
│                                      │
│ 2. Salva no PostgreSQL               │
└──────────────────────────────────────┘
```

### Código:

```python
# scripts/persist_history_with_curated_db.py

# Passo 1: Tenta banco curado
version_data = query_homologated_version(cursor, package_name)

if version_data:
    print(f"✅ Encontrado no banco curado")
    source = "CURATED_DB"
else:
    # Passo 2: Fallback para OSV API
    print(f"⚠️ Consultando OSV API...")
    version_data = query_osv(package_name, installed_version)
    source = "OSV_API"
```

### Vantagens:

✅ **Controle total:** Equipe aprova versões antes de usar  
✅ **Rastreabilidade:** Quem aprovou, quando, por quê  
✅ **Governança:** Demonstra processo formal para TCC  
✅ **Fallback seguro:** Se não estiver no banco, usa OSV  
✅ **Menor impacto:** Equipe escolhe versões compatíveis com legado

### Desvantagens:

❌ Requer manutenção do banco curado  
❌ Equipe precisa aprovar novas versões manualmente

---

## 🛠️ Como Usar Cada Estratégia

### **Estratégia 1: OSV API (Atual)**

O workflow já usa por padrão. **Nenhuma mudança necessária.**

```bash
# Local
python framework.py

# GitHub Actions
# Já configurado em: .github/workflows/ai-agent-security-pipeline.yml
```

---

### **Estratégia 2: Banco Curado + OSV**

#### **Passo 1: Popular banco curado (local)**

```bash
# Subir PostgreSQL
docker-compose up -d

# Criar schema
docker exec -i remediation-db psql -U postgres -d remediation < database/schema.sql

# Popular versões homologadas
docker exec -i remediation-db psql -U postgres -d remediation < database/seed_homologated_versions.sql

# Verificar
docker exec -it remediation-db psql -U postgres -d remediation -c "SELECT * FROM homologated_versions;"
```

**Saída esperada:**
```
 package_name        | ecosystem | safe_version | approved_by     | notes
---------------------+-----------+--------------+-----------------+-------
 guzzlehttp/guzzle   | PHP       | 6.5.8        | Security Team   | Última versão 6.x...
 guzzlehttp/guzzle   | PHP       | 7.4.5        | Security Team   | Versão 7.x...
 express             | Node.js   | 4.18.2       | Security Team   | Última versão 4.x...
```

#### **Passo 2: Executar framework com banco curado (local)**

```bash
# Opção A: Substituir manualmente o script
cp scripts/persist_history_with_curated_db.py scripts/persist_history.py

# Executar
python framework.py

# Restaurar original (se quiser voltar)
git checkout scripts/persist_history.py
```

**OU usar diretamente:**

```bash
# Modificar framework.py temporariamente para usar persist_history_with_curated_db.py
# (não recomendado, melhor usar variável de ambiente no workflow)
```

#### **Passo 3: Habilitar no GitHub Actions**

Já está configurado! O workflow detecta a variável `USE_CURATED_DB`:

```yaml
# .github/workflows/ai-agent-security-pipeline.yml

- name: Seed Homologated Versions (Curated Database)
  run: |
    psql -h localhost -U postgres -d remediation -f database/seed_homologated_versions.sql

- name: Run Remediation Framework
  env:
    USE_CURATED_DB: "true"  # ← Habilitar banco curado
  run: |
    if [ "$USE_CURATED_DB" = "true" ]; then
      cp scripts/persist_history_with_curated_db.py scripts/persist_history.py
    fi
    python framework.py
```

---

## 📝 Adicionando Novas Versões Homologadas

### Manualmente (SQL):

```sql
INSERT INTO homologated_versions (package_name, ecosystem, safe_version, approved_by, notes)
VALUES (
    'sua-lib/pacote',
    'PHP',
    '2.5.8',
    'João Silva',
    'Testado em homolog. Compatível com PHP 7.4+'
);
```

### Via script Python (futuro):

```python
# scripts/approve_version.py
import psycopg2

def approve_version(package, ecosystem, version, approver, notes):
    conn = psycopg2.connect(...)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO homologated_versions (
            package_name, ecosystem, safe_version, 
            approved_by, notes
        ) VALUES (%s, %s, %s, %s, %s)
    """, (package, ecosystem, version, approver, notes))
    
    conn.commit()
```

---

## 🎯 Recomendação para o TCC

### Para Demonstração Acadêmica:

**USE A ESTRATÉGIA 2 (Banco Curado)** porque:

1. ✅ **Demonstra governança:** Processo formal de aprovação
2. ✅ **Auditoria completa:** Quem, quando, por quê
3. ✅ **Diferencial acadêmico:** Não é só "chamar API do Google"
4. ✅ **Rastreabilidade:** Mostra maturidade DevSecOps
5. ✅ **Compliance:** Necessário para SOC2, ISO 27001, LGPD

### Argumento para Banca:

> *"Ao contrário de soluções como Dependabot que apenas chamam APIs públicas, nosso framework implementa um **processo de homologação curado** onde a equipe de segurança valida manualmente versões seguras antes de aplicá-las em produção. Isso garante **compatibilidade com sistemas legados** e atende requisitos de **compliance** e **governança**."*

---

## 🔄 Mudança Entre Estratégias

### Local:

```bash
# Usar OSV API (padrão)
git checkout scripts/persist_history.py

# Usar banco curado
cp scripts/persist_history_with_curated_db.py scripts/persist_history.py
```

### GitHub Actions:

```yaml
# Editar .github/workflows/ai-agent-security-pipeline.yml

env:
  USE_CURATED_DB: "false"  # OSV API apenas
  # ou
  USE_CURATED_DB: "true"   # Banco curado + OSV
```

---

## 📊 Logs de Execução

### Estratégia 1 (OSV API):

```
🔍 Buscando versão para guzzlehttp/guzzle...
  ✅ Encontrado na OSV API
```

### Estratégia 2 (Banco Curado):

```
🔍 Buscando versão para guzzlehttp/guzzle...
  ✅ Encontrado no banco curado (aprovado por: Security Team)

🔍 Buscando versão para pacote-desconhecido...
  ⚠️ Não encontrado no banco curado, consultando OSV API...
  ✅ Encontrado na OSV API
```

---

## 🎓 Conclusão

- **Estratégia 1:** Simples, funcional, boa para PoC
- **Estratégia 2:** Completa, governança, melhor para TCC

**Para seu TCC, recomendo usar Estratégia 2** para demonstrar maturidade e diferencial competitivo.

