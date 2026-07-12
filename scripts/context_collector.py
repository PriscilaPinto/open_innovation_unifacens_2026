import os
import json


# ==========================================
# DETECT MULTIPLE ECOSYSTEMS
# ==========================================

def detect_ecosystems():
    """
    Detecta TODOS os ecossistemas presentes no projeto.
    Retorna lista, não apenas um.
    
    Multi-linguagem verdadeiro: se tiver PHP + Node + Python,
    retorna os 3 para serem processados separadamente.
    """
    ecosystems = []

    # ==========================================
    # PHP / COMPOSER
    # ==========================================
    if os.path.exists("composer.json"):
        ecosystems.append({
            "ecosystem": "php",
            "curated_ecosystem": "PHP",
            "osv_ecosystem": "Packagist",
            "package_manager": "composer",
            "lockfile": "composer.lock",
            "validation_command": ["php", "index.php"],
            "manifest_file": "composer.json"
        })

    # ==========================================
    # NODE / NPM
    # ==========================================
    if os.path.exists("package.json"):
        ecosystems.append({
            "ecosystem": "node",
            "curated_ecosystem": "Node.js",
            "osv_ecosystem": "npm",
            "package_manager": "npm",
            "lockfile": "package-lock.json",
            "validation_command": ["npm", "test"],
            "manifest_file": "package.json"
        })

    # ==========================================
    # PYTHON / PIP
    # ==========================================
    if os.path.exists("requirements.txt"):
        ecosystems.append({
            "ecosystem": "python",
            "curated_ecosystem": "Python",
            "osv_ecosystem": "PyPI",
            "package_manager": "pip",
            "lockfile": "requirements.txt",
            "validation_command": ["pytest"],
            "manifest_file": "requirements.txt"
        })

    return ecosystems


def detect_ecosystem():
    """
    Backwards compatible: retorna o primeiro (ou None).
    Mantém compatibilidade com código antigo.
    """
    ecosystems = detect_ecosystems()
    return ecosystems[0] if ecosystems else {
        "ecosystem": None,
        "curated_ecosystem": None,
        "osv_ecosystem": None,
        "package_manager": None,
        "lockfile": None,
        "validation_command": None
    }


# ==========================================
# DETECT PACKAGE ECOSYSTEM BY REPORT
# ==========================================
def detect_vulnerability_ecosystem(vulnerability_json):
    """
    Detecta qual ecossistema uma vulnerabilidade pertence
    baseado no arquivo detectado pelo Trivy (composer.lock, package-lock.json, etc).
    
    Entrada (do Trivy report):
    {
      "Type": "composer",
      "Target": "composer.lock",
      "Vulnerabilities": [...]
    }
    """
    vuln_type = vulnerability_json.get("Type", "").lower()
    target = vulnerability_json.get("Target", "").lower()

    if "composer" in vuln_type or "composer.lock" in target or "composer.json" in target:
        return "PHP"
    elif "npm" in vuln_type or "package" in target:
        return "Node.js"
    elif "pip" in vuln_type or "requirements" in target:
        return "Python"
    else:
        return None


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":
    ecosystems = detect_ecosystems()
    print(f"Detectados {len(ecosystems)} ecossistema(s):")
    for eco in ecosystems:
        print(f"  - {eco['curated_ecosystem']} ({eco['package_manager']})")
