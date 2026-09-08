import re
from typing import Dict, Any

class PromptSanitizer:
    """
    Sanitizes untrusted repository and vulnerability content to defend against
    direct and indirect prompt injection attacks.
    """

    SUSPICIOUS_PATTERNS = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"system\s*prompt",
        r"you\s+are\s+now\s+a",
        r"delete\s+all",
        r"drop\s+database",
        r"bypass\s+security",
        r"eval\(",
        r"exec\("
    ]

    @classmethod
    def sanitize_untrusted_text(cls, text: str, max_length: int = 1500) -> str:
        """
        Strips control characters, neutralizes known injection phrases,
        and clamps token length.
        """
        if not text:
            return ""

        cleaned = str(text).strip()
        # Truncate to maximum length
        cleaned = cleaned[:max_length]

        # Neutralize common injection phrases
        for pattern in cls.SUSPICIOUS_PATTERNS:
            cleaned = re.sub(pattern, "[FILTERED_INSTRUCTION]", cleaned, flags=re.IGNORECASE)

        # Escape Markdown injection or raw template tags
        cleaned = cleaned.replace("```", "'''")
        cleaned = cleaned.replace("<script", "&lt;script")
        return cleaned

    @classmethod
    def build_structured_prompt(
        cls,
        task_title: str,
        package: str,
        target_version: str,
        findings_summary: str,
        environment: str,
        criticality: str
    ) -> str:
        """
        Constructs a strictly demarcated prompt with distinct trusted metadata
        and sanitized untrusted input blocks.
        """
        clean_title = cls.sanitize_untrusted_text(task_title, max_length=200)
        clean_pkg = cls.sanitize_untrusted_text(package or "N/A", max_length=100)
        clean_ver = cls.sanitize_untrusted_text(target_version or "latest", max_length=50)
        clean_findings = cls.sanitize_untrusted_text(findings_summary, max_length=2000)

        prompt = f"""### TRUSTED SYSTEM INSTRUCTION:
You are the LineSec Vulnerability Reasoning Layer.
Analyze the following security task and return a strict JSON object with your analysis.
Do not execute shell commands or output arbitrary code.

### TRUSTED CONTEXT:
- Target Environment: {environment}
- Asset Criticality: {criticality}

### UNTRUSTED SCANNER FINDINGS & VULNERABILITY DATA:
```
Task Title: {clean_title}
Package: {clean_pkg}
Target Version: {clean_ver}
Findings Details:
{clean_findings}
```

### REQUIRED JSON RESPONSE SCHEMA:
{{
  "summary": "Concise 1-2 sentence executive summary of the vulnerability",
  "root_cause": "Underlying software weakness or flaw mechanism",
  "business_impact": "Impact on confidentiality, integrity, availability, or operations",
  "recommended_action": "Specific upgrade, configuration, or patch instruction",
  "estimated_effort": "e.g., 30 minutes, 2 hours, 1 day",
  "deployment_risk": "LOW, MEDIUM, or HIGH",
  "reasoning": "Technical justification for remediation prioritization",
  "verification_guidance": "How developers can verify the fix succeeded post-patch"
}}
"""
        return prompt
