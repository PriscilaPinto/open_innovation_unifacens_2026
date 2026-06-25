import json
import os

from openai import OpenAI


print("Starting AI Analyzer...")


# ==========================================
# LOAD OPENROUTER CLIENT
# ==========================================

client = OpenAI(
    api_key=os.getenv("GEMINI_API_KEY"),
    base_url="https://openrouter.ai/api/v1"
)


print("OpenRouter initialized")


# ==========================================
# SAMPLE CONTEXT
# ==========================================

context = {
    "ecosystem": "php",
    "package_manager": "composer",
    "runtime": "php >=5.5",
    "package": "guzzlehttp/guzzle",
    "installed_version": "6.3.0",
    "fixed_versions": [
        "6.5.8",
        "7.0.1"
    ],
    "severity": "HIGH"
}


# ==========================================
# PROMPT
# ==========================================

prompt = f"""
You are an autonomous DevSecOps remediation agent.

Analyze the following vulnerability remediation scenario.

Repository Context:
{json.dumps(context, indent=2)}

Your task:
- choose the safest remediation strategy
- minimize breaking changes
- prioritize legacy compatibility
- recommend the best target version
- estimate remediation risk
- explain reasoning

Respond ONLY in valid JSON.

Expected format:

{{
  "recommended_strategy": "...",
  "recommended_version": "...",
  "risk_level": "...",
  "confidence": 0.0,
  "reasoning": "..."
}}
"""


print("Sending request to OpenRouter...")


# ==========================================
# INVOKE MODEL
# ==========================================

try:

    response = client.chat.completions.create(
        model="google/gemini-2.5-flash",
        max_tokens=500,
        temperature=0.1,
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )

    print()
    print("===== AI RESPONSE =====")
    print(response.choices[0].message.content)

except Exception as e:

    print()
    print("===== AI ERROR =====")
    print(e)