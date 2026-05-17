import json
import os
import subprocess
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_google_genai import ChatGoogleGenerativeAI

def executar_framework_autonomo():
    print("\n🤖 [FASE 1] Iniciando Framework de Remediação Autônoma (Foco: SCA)...")

    report_path = 'reports/report.json'
    composer_json_path = 'composer.json'

    if not os.path.exists(report_path):
        print("❌ Erro: Relatório 'reports/report.json' não encontrado.")
        return

    if not os.path.exists(composer_json_path):
        print(f"❌ Erro: O arquivo '{composer_json_path}' não existe no diretório raiz.")
        return

    # Lendo dados do Trivy
    with open(report_path, 'r', encoding='utf-8') as f:
        trivy_data = json.load(f)

    vulnerabilities = []
    for result in trivy_data.get('Results', []):
        # Garante que estamos pegando vulnerabilidades de pacotes/dependências (SCA)
        if result.get('Type') in ['composer', 'node-pkg', 'pip'] or 'Vulnerabilities' in result:
            if 'Vulnerabilities' in result:
                vulnerabilities.extend(result['Vulnerabilities'])

    if not vulnerabilities:
        print("✅ Nenhuma vulnerabilidade de dependência (SCA) foi encontrada no relatório.")
        print("📦 Criando arquivo fictício apenas para não quebrar o upload do artefato.")
        with open("index_remediated.php", "w") as f: f.write("<?php // Ambiente Seguro ?>")
        return

    print(f"🔍 Mapeadas {len(vulnerabilities)} vulnerabilidades de SCA no ambiente.")

    # Lendo o composer.json atual para dar contexto à IA
    with open(composer_json_path, 'r', encoding='utf-8') as f:
        composer_atual = f.read()

    # Chamando a inteligência do LangChain (Gemini 2.5 Flash)
    llm = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.1)

    prompt_template = PromptTemplate.from_template(
        """
        Você é um agente de IA autônomo especialista em DevSecOps, AppSec e gerenciamento de dependências (SCA).
        Sua missão é analisar o relatório de vulnerabilidades e propor os comandos exatos de atualização do Composer para sanar as CVEs listadas.

        [DIRETRIZES OBRIGATÓRIAS]
        1. Analise as dependências atuais e as vulnerabilidades encontradas.
        2. Proponha comandos cirúrgicos usando `composer update <nome-do-pacote>` para mitigar os riscos atualizando para as versões seguras recomendadas.
        3. Se houver mais de um pacote afetado, envie um comando por linha.
        4. FORMATO DE SAÍDA: Retorne APENAS as linhas de comando prontas para execução no terminal. Não inclua blocos de código markdown (```bash), explicações textuais ou saudações.

        [ARQUIVO COMPOSER.JSON ATUAL]
        {composer_json}

        [RELATÓRIO DE VULNERABILIDADES DO TRIVY]
        {vulns}

        Gere os comandos de remediação do Composer agora:
        """
    )

    chain = prompt_template | llm | StrOutputParser()

    print("🧠 [FASE 2] IA analisando CVEs e calculando atualizações de pacotes...")
    comandos_remediacao = chain.invoke({
        "composer_json": composer_atual,
        "vulns": json.dumps(vulnerabilities, indent=2)
    })

    print("\n🖥️ [FASE 3] Executando comandos de remediação gerados pela IA:")
    linhas_comandos = [cmd.strip() for cmd in comandos_remediacao.strip().split('\n') if cmd.strip()]

    # Executa cada comando proposto pela IA no ambiente isolado do runner
    sucesso_automacao = True
    for comando in linhas_comandos:
        print(f"🚀 Executando: {comando}")
        try:
            # Divide a string em argumentos para o subprocess
            args = comando.split()
            # Adiciona a flag para evitar travamento interativo
            if "--no-interaction" not in args:
                args.append("--no-interaction")
                
            resultado = subprocess.run(args, capture_output=True, text=True, check=True)
            print(f"✅ Sucesso na execução!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Falha ao rodar comando de remediação: {comando}")
            print(f"Erro do Composer: {e.stderr}")
            sucesso_automacao = False

    if sucesso_automacao:
        print("\n💾 [FASE 4] Remediação SCA aplicada! Arquivos composer.json e composer.lock foram atualizados.")
        # Cria um arquivo flag para manter compatibilidade com o Job 3 do YAML antigo se necessário
        with open("index_remediated.php", "w") as f:
            f.write("<?php // Patch de dependencias aplicado com sucesso no composer.lock ?>")
    else:
        print("\n⚠️ Algumas dependências falharam na atualização automática. Revisar logs.")

if __name__ == "__main__":
    executar_framework_autonomo()