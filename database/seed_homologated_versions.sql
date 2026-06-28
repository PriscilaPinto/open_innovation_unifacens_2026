-- ==========================================
-- SEED: Versões Homologadas (Curadas)
-- ==========================================
-- Popula banco com versões testadas e aprovadas
-- pela equipe de segurança para uso em produção
-- ==========================================

-- Limpar dados existentes (opcional)
-- TRUNCATE TABLE homologated_versions;

-- ==========================================
-- PHP / COMPOSER PACKAGES
-- ==========================================

INSERT INTO homologated_versions (package_name, ecosystem, safe_version, approved_by, notes) VALUES
('guzzlehttp/guzzle', 'PHP', '6.5.8', 'Security Team', 'Última versão 6.x sem breaking changes. Corrige CVE-2022-29248, CVE-2022-31042, CVE-2022-31043, CVE-2022-31090, CVE-2022-31091'),
('guzzlehttp/guzzle', 'PHP', '7.4.5', 'Security Team', 'Versão 7.x mais recente. Requer PHP 7.2.5+. Mudanças significativas na API'),
('guzzlehttp/guzzle', 'PHP', '7.8.1', 'Security Team', 'Última versão estável (Dez 2023). Requer PHP 7.2.5+'),
('monolog/monolog', 'PHP', '2.9.2', 'Security Team', 'Versão 2.x estável. Compatível com PHP 7.4+'),
('monolog/monolog', 'PHP', '3.5.0', 'Security Team', 'Versão 3.x mais recente. Requer PHP 8.1+'),
('symfony/http-foundation', 'PHP', '5.4.35', 'Security Team', 'Versão LTS Symfony 5.4 (suporte até Nov 2025)'),
('symfony/http-foundation', 'PHP', '6.4.3', 'Security Team', 'Versão LTS Symfony 6.4 (suporte até Nov 2027)'),
('laravel/framework', 'PHP', '9.52.16', 'Security Team', 'Laravel 9 LTS (suporte até Fev 2025)'),
('laravel/framework', 'PHP', '10.48.4', 'Security Team', 'Laravel 10 LTS (suporte até Fev 2026)'),
('psr/log', 'PHP', '3.0.0', 'Security Team', 'Interface PSR-3 padrão para logging'),
-- ==========================================
-- NODE.JS / NPM PACKAGES
-- ==========================================
('express', 'Node.js', '4.18.2', 'Security Team', 'Última versão 4.x estável. Amplamente testado'),
('express', 'Node.js', '4.19.2', 'Security Team', 'Versão mais recente (2024)'),
('lodash', 'Node.js', '4.17.21', 'Security Team', 'Corrige CVE-2021-23337 (command injection)'),
('axios', 'Node.js', '1.6.7', 'Security Team', 'Última versão 1.x. Corrige vulnerabilidades de SSRF'),
('moment', 'Node.js', '2.29.4', 'Security Team', 'Última versão. AVISO: Projeto em modo manutenção. Considere date-fns ou luxon'),
('react', 'Node.js', '18.2.0', 'Security Team', 'React 18 estável'),
-- ==========================================
-- PYTHON / PIP PACKAGES
-- ==========================================
('flask', 'Python', '2.3.3', 'Security Team', 'Versão 2.x estável. Corrige CVE-2023-30861'),
('flask', 'Python', '3.0.2', 'Security Team', 'Flask 3.x mais recente. Requer Python 3.8+'),
('django', 'Python', '4.2.10', 'Security Team', 'Django 4.2 LTS (suporte até Abril 2026)'),
('django', 'Python', '5.0.2', 'Security Team', 'Django 5.x mais recente. Requer Python 3.10+'),
('requests', 'Python', '2.31.0', 'Security Team', 'Versão mais recente. Corrige vulnerabilidades SSL'),
('sqlalchemy', 'Python', '2.0.28', 'Security Team', 'SQLAlchemy 2.x estável'),
('jinja2', 'Python', '3.1.3', 'Security Team', 'Última versão. Corrige sandbox escape')

-- ==========================================
-- REGRAS DE PRIORIZAÇÃO
-- ==========================================
-- O script persist_history_with_curated_db.py prioriza:
-- 1. Versão mais recente no banco curado (ORDER BY approved_at DESC)
-- 2. Se não encontrar, consulta OSV API como fallback
-- ==========================================

-- ==========================================
-- COMO USAR:
-- ==========================================
-- 1. Local (teste):
--    docker exec -i remediation-db psql -U postgres -d remediation < database/seed_homologated_versions.sql
--
-- 2. GitHub Actions:
--    Já executado automaticamente no workflow (veja step "Seed Homologated Versions")
-- ==========================================
