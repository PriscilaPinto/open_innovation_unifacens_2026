import os
import json


# ==========================================
# DETECT ECOSYSTEM
# ==========================================

def detect_ecosystem():

    context = {
        "ecosystem": None,
        "package_manager": None,
        "lockfile": None,
        "validation_command": None
    }

    # ==========================================
    # PHP / COMPOSER
    # ==========================================

    if os.path.exists("composer.json"):

        context["ecosystem"] = "php"
        context["package_manager"] = "composer"
        context["lockfile"] = "composer.lock"
        context["validation_command"] = [
            "php",
            "index.php"
        ]

    # ==========================================
    # NODE / NPM
    # ==========================================

    elif os.path.exists("package.json"):

        context["ecosystem"] = "node"
        context["package_manager"] = "npm"
        context["lockfile"] = "package-lock.json"
        context["validation_command"] = [
            "npm",
            "test"
        ]

    # ==========================================
    # PYTHON / PIP
    # ==========================================

    elif os.path.exists("requirements.txt"):

        context["ecosystem"] = "python"
        context["package_manager"] = "pip"
        context["lockfile"] = "requirements.txt"
        context["validation_command"] = [
            "pytest"
        ]

    return context


# ==========================================
# MAIN
# ==========================================

if __name__ == "__main__":

    context = detect_ecosystem()

    print(json.dumps(context, indent=4))