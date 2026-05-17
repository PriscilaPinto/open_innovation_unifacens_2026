import json
import os
import subprocess
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_google_genai import ChatGoogleGenerativeAI

def executar_framework_autonomo():
    print("\n🤖 [FASE 1] Iniciando Framework de Remediação Autônoma (Foco Puro: SCA)...")

    report_path = 'reports/report.json'
    composer_json_path = 'composer.json'

    if not os.path.exists(report_path):
        print("❌ Erro: Relatório 'reports/report.json' não encontrado.")
        return

    if not os.path.exists(composer_json_path):
        print(f"❌ Erro: O arquivo '{composer_json_path}' não existe.")
        return

    # Lendo dados do Trivy
    with open(report_path, 'r', encoding='utf-8') as f:
        trivy_data = json.load(f)

    vulnerabilities = []
    for result in trivy_data.get('Results', []):
        if 'Vulnerabilities' in result:
            vulnerabilities.extend(result['Vulnerabilities'])

    if not vulnerabilities:
        print("✅ Nenhuma vulnerabilidade de dependência (SCA) encontrada.")
        return

    print(f"🔍 Mapeadas {len(vulnerabilities)} vulnerabilidades de SCA no ambiente.")

    with open(composer_json_path, 'r', encoding='utf-8') as f:
        composer_atual = f.read()

    llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.1)

    prompt_template = PromptTemplate.from_template(
        """
        Você é um agente de IA especialista em DevSecOps e gerenciamento de dependências (SCA).
        Sua missão é propor os comandos exatos de atualização do Composer para sanar as CVEs listadas.

        [DIRETRIZES OBRIGATÓRIAS]
        1. Proponha comandos cirúrgicos usando `composer update <nome-do-pacote>`.
        2. FORMATO DE SAÍDA: Retorne APENAS as linhas de comando prontas para execução. Não inclua markdown (```bash) ou textos explicativos.

        [ARQUIVO COMPOSER.JSON ATUAL]
        {composer_json}

        [RELATÓRIO DE VULNERABILIDADES DO TRIVY]
        {vulns}
        """
    )

    chain = prompt_template | llm | StrOutputParser()

    print("🧠 [FASE 2] IA calculando atualizações de pacotes...")
    comandos_remediacao = chain.invoke({
        "composer_json": composer_atual,
        "vulns": json.dumps(vulnerabilities, indent=2)
    })

    print("\n🖥️ [FASE 3] Executando comandos de remediação:")
    linhas_comandos = [cmd.strip() for cmd in comandos_remediacao.strip().split('\n') if cmd.strip()]

    sucesso_automacao = True
    for comando in linhas_comandos:
        if "composer update" in comando:
            print(f"🚀 Executando comando de terminal: {comando}")
            try:
                args = comando.split()
                if "--no-interaction" not in args:
                    args.append("--no-interaction")
                
                # Executa a atualização real do pacote no ambiente isolado do runner
                subprocess.run(args, capture_output=True, text=True, check=True)
                print(f"✅ Sucesso na execução do update!")
            except subprocess.CalledProcessError as e:
                print(f"❌ Falha ao rodar: {comando}. Erro: {e.stderr}")
                sucesso_automacao = False

    if sucesso_automacao:
        print("\n💾 [FASE 4] Remediação SCA concluída com sucesso nos arquivos do Composer!")
    else:
        print("\n⚠️ Algumas dependências falharam na atualização automática. Revisar logs.")

if __name__ == "__main__":
    executar_framework_autonomo()