INSERT INTO homologated_versions
    (package_name, ecosystem, safe_version, approved_by, notes)
VALUES
    (
        'guzzlehttp/guzzle',
        'PHP',
        '7.15.2',
        'Security Team',
        'Versão corrigida identificada pelo Trivy e homologada com base nas evidências do OSV. CVEs 7.12.1, 7.12.3, 7.14.2, 7.15.1 e 7.15.2 só possuem fix na major 7 — não existe correção na linha 6.x. Requer atualização conjunta com guzzlehttp/psr7:2.12.3.'
    ),

    (
        'guzzlehttp/psr7',
        'PHP',
        '2.12.3',
        'Security Team',
        'Versão corrigida identificada pelo Trivy e pelo OSV para a vulnerabilidade GHSA-34xg-wgjx-8xph.'
    ),

    (
        'requests',
        'Python',
        '2.33.0',
        'Security Team',
        'Versão corrigida identificada pelo Trivy e superior à versão mínima corrigida indicada pelo OSV (2.32.4).'
    ),

    (
        'python-dotenv',
        'Python',
        '1.2.2',
        'Security Team',
        'Versão corrigida identificada pelo Trivy e homologada com base nas evidências do OSV.'
    )

ON CONFLICT (package_name, ecosystem, safe_version) DO NOTHING;
