import json
import os
import time
import uuid
import subprocess
import psycopg2

from openai import OpenAI


def executar_pipeline_hibrida_seguranca():

    print("\n🤖 [FASE 1] Iniciando Framework de Remediação...")

    report_path = 'reports/report.json'

    if not os.path.exists(report_path):
        print("❌ Erro: Relatório 'reports/report.json' não encontrado.")
        return

    with open(report_path, 'r', encoding='utf-8') as f:
        trivy_data = json.load(f)

    vulnerabilities = []
    ecossistema = "Desconhecido"
    arquivo_alvo_sugerido = "patch_seguranca"
    tecnologia_detectada = False

    for result in trivy_data.get('Results', []):

        target_type = result.get('Type', '').lower()

        if 'Vulnerabilities' in result:

            for vuln in result['Vulnerabilities']:

                vulnerabilities.append({
                    "VulnerabilityID": vuln.get("VulnerabilityID", "N/A"),
                    "PkgName": vuln.get("PkgName", "Desconhecido"),
                    "InstalledVersion": vuln.get("InstalledVersion", "N/A"),
                    "FixedVersion": vuln.get("FixedVersion", ""),
                    "Severity": vuln.get("Severity", "UNKNOWN"),
                    "Description": vuln.get("Description", "Sem descrição.")
                })

        if not tecnologia_detectada:

            if 'composer' in target_type:
                ecossistema = "PHP (Composer)"
                arquivo_alvo_sugerido = "virtual_patch_bootstrap.php"
                tecnologia_detectada = True

            elif 'npm' in target_type or 'yarn' in target_type:
                ecossistema = "Node.js (NPM)"
                arquivo_alvo_sugerido = "virtual_patch_middleware.js"
                tecnologia_detectada = True

            elif 'pip' in target_type or 'poetry' in target_type:
                ecossistema = "Python (PIP)"
                arquivo_alvo_sugerido = "virtual_patch_interceptor.py"
                tecnologia_detectada = True

    if not vulnerabilities:
        print("✅ Nenhuma vulnerabilidade detectada.")
        return

    print(f"📦 Ecossistema Detectado: {ecossistema}")
    print(f"🔍 Mapeadas {len(vulnerabilities)} vulnerabilidades.")

    vulnerabilities_para_ia = []
    historico_auditoria = []

    print("\n🛠️ [MOTOR DE DECISÃO] Iniciando análise...")

    for vuln in vulnerabilities:

        pkg = vuln["PkgName"]
        fixed_ver = vuln["FixedVersion"]
        cve = vuln["VulnerabilityID"]
        severity = vuln["Severity"]
        installed = vuln["InstalledVersion"]

        if fixed_ver and ecossistema == "PHP (Composer)":

            print(f"⚡ Tentando atualização de {pkg}...")

            comando = f"composer require {pkg}:{fixed_ver} --with-dependencies --no-interaction --no-progress"

            resultado_cli = subprocess.run(
                comando,
                shell=True,
                capture_output=True,
                text=True
            )

            if resultado_cli.returncode == 0:

                print(f"✅ Biblioteca {pkg} atualizada.")

                historico_auditoria.append({
                    "cve_id": cve,
                    "package_name": pkg,
                    "old_version": installed,
                    "patched_version": fixed_ver,
                    "severity_level": severity,
                    "status": "Atualizado",
                    "justificativa": f"Atualização automática aplicada para {fixed_ver}."
                })

                continue

            else:
                print(f"⚠️ Falha no hardening real. Escalando para Virtual Patch.")

        print(f"🛡️ Virtual patch necessário para {cve}")

        vulnerabilities_para_ia.append(vuln)

        historico_auditoria.append({
            "cve_id": cve,
            "package_name": pkg,
            "old_version": installed,
            "patched_version": "Virtual Patched",
            "severity_level": severity,
            "status": "Virtual Patched",
            "justificativa": "Mitigação via IA generativa."
        })

    if vulnerabilities_para_ia:

        print(f"\n🧠 [FASE 2] Gerando virtual patch...")

        client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.getenv("GEMINI_API_KEY")
        )

        prompt = f"""
Você é um especialista em AppSec e DevSecOps.

Crie um virtual patch para o ecossistema:
{ecossistema}

Vulnerabilidades:
{json.dumps(vulnerabilities_para_ia, indent=2)}

Retorne SOMENTE o código puro do patch.
"""

        max_tentativas = 5
        base_delay = 2

        codigo_patch = ""

        for tentativa in range(max_tentativas):

            try:

                resposta = client.chat.completions.create(

                    model="google/gemini-2.0-flash",

                    messages=[
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ]
                )

                codigo_patch = resposta.choices[0].message.content

                break

            except Exception as e:

                if tentativa == max_tentativas - 1:
                    print(f"❌ Falha fatal: {e}")
                    return

                delay = base_delay * (2 ** tentativa)

                print(f"⚠️ Tentativa falhou. Retry em {delay}s...")

                time.sleep(delay)

        codigo_limpo = (
            codigo_patch
            .replace("```php", "")
            .replace("```javascript", "")
            .replace("```python", "")
            .replace("```", "")
            .strip()
        )

        print(f"💾 Salvando patch: {arquivo_alvo_sugerido}")

        with open(arquivo_alvo_sugerido, 'w', encoding='utf-8') as f:
            f.write(codigo_limpo)

        with open('patch_meta.json', 'w', encoding='utf-8') as f:
            json.dump({
                "arquivo_gerado": arquivo_alvo_sugerido,
                "ecossistema": ecossistema
            }, f)

        print("✅ Virtual patch gerado com sucesso!")

    else:

        print("\n✅ Todas vulnerabilidades foram resolvidas via atualização.")

    print("\n🗄️ [FASE 5] Persistindo auditoria...")

    try:
        # Usa db.py para conectar (consistente com o resto do framework)
        import sys
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from db import connect_db
        conexao = connect_db()

        cursor = conexao.cursor()

        execution_uuid = str(uuid.uuid4())

        cursor.execute(
            """
            INSERT INTO pipeline_executions
            (execution_uuid, repository_name, final_status, initial_vuln_count, ended_at)
            VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
            RETURNING id;
            """,
            (
                execution_uuid,
                "open_innovation_virtual",
                "Sucesso",
                len(vulnerabilities)
            )
        )

        execution_id = cursor.fetchone()[0]

        for audit in historico_auditoria:

            cursor.execute(
                """
                INSERT INTO remediated_vulnerabilities
                (
                    execution_id,
                    cve_id,
                    package_name,
                    old_version,
                    patched_version,
                    severity_level,
                    ai_justification,
                    remediation_status
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s);
                """,
                (
                    execution_id,
                    audit["cve_id"],
                    audit["package_name"],
                    audit["old_version"],
                    audit["patched_version"],
                    audit["severity_level"],
                    audit["justificativa"],
                    audit["status"]
                )
            )

        conexao.commit()

        cursor.close()
        conexao.close()

        print("✅ Auditoria salva com sucesso!")

    except Exception as db_err:

        print(f"⚠️ Falha banco: {db_err}")


if __name__ == "__main__":
    executar_pipeline_hibrida_seguranca()