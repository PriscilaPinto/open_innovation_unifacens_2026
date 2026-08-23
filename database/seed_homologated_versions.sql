```sql
-- Versões homologadas pela equipe de segurança
-- As versões abaixo representam versões aprovadas para remediação.
-- ON CONFLICT DO NOTHING: seguro para rodar múltiplas vezes sem duplicar

INSERT INTO homologated_versions
(package_name, ecosystem, safe_version, approved_by, notes)
VALUES

-- ============================================================
-- PHP / Composer
-- ============================================================

('guzzlehttp/guzzle',
 'PHP',
 '7.15.2',
 'Security Team',
 'Versão mínima homologada que corrige as vulnerabilidades identificadas no scan atual do Trivy.'),

('guzzlehttp/psr7',
 'PHP',
 '2.12.3',
 'Security Team',
 'Versão mínima homologada que corrige as vulnerabilidades identificadas no scan atual do Trivy.'),

('monolog/monolog',
 'PHP',
 '2.9.2',
 'Security Team',
 'Versão 2.x estável. Compatível com PHP 7.4+.'),

('monolog/monolog',
 'PHP',
 '3.5.0',
 'Security Team',
 'Versão 3.x. Requer PHP 8.1+.'),

('symfony/http-foundation',
 'PHP',
 '5.4.35',
 'Security Team',
 'LTS Symfony 5.4.'),

('symfony/http-foundation',
 'PHP',
 '6.4.3',
 'Security Team',
 'LTS Symfony 6.4.'),

('laravel/framework',
 'PHP',
 '9.52.16',
 'Security Team',
 'Laravel 9 LTS.'),

('laravel/framework',
 'PHP',
 '10.48.4',
 'Security Team',
 'Laravel 10 LTS.'),

('psr/log',
 'PHP',
 '3.0.0',
 'Security Team',
 'Interface PSR-3.'),


-- ============================================================
-- Node.js / npm
-- ============================================================

('express',
 'Node.js',
 '4.19.2',
 'Security Team',
 'Última versão 4.x estável.'),

('lodash',
 'Node.js',
 '4.17.21',
 'Security Team',
 'Versão homologada para correção de vulnerabilidades conhecidas.'),

('axios',
 'Node.js',
 '1.6.7',
 'Security Team',
 'Versão homologada para correção de vulnerabilidades SSRF.'),

('moment',
 'Node.js',
 '2.29.4',
 'Security Team',
 'Última versão do projeto em manutenção.'),

('react',
 'Node.js',
 '18.2.0',
 'Security Team',
 'React 18 estável.'),


-- ============================================================
-- Python / pip
-- ============================================================

('flask',
 'Python',
 '3.0.2',
 'Security Team',
 'Flask 3.x. Requer Python 3.8+.'),

('django',
 'Python',
 '4.2.10',
 'Security Team',
 'Django 4.2 LTS.'),

('requests',
 'Python',
 '2.33.0',
 'Security Team',
 'Versão mínima homologada que corrige as vulnerabilidades identificadas no scan atual do Trivy.'),

('sqlalchemy',
 'Python',
 '2.0.28',
 'Security Team',
 'SQLAlchemy 2.x estável.'),

('jinja2',
 'Python',
 '3.1.3',
 'Security Team',
 'Versão homologada para correção de vulnerabilidades conhecidas.'),

('python-dotenv',
 'Python',
 '1.2.2',
 'Security Team',
 'Versão homologada para correção da vulnerabilidade identificada no scan atual do Trivy.')

ON CONFLICT (package_name, ecosystem, safe_version) DO NOTHING;
```
