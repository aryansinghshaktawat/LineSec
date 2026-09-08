import re
import json
from typing import Optional, Tuple

class ManifestPatcher:
    """
    Safely modifies package manifests (requirements.txt, package.json)
    preserving existing operator semantics, extras, comments, and formatting.
    """

    @staticmethod
    def patch_requirements_txt(content: str, package_name: str, target_version: str) -> Tuple[str, bool]:
        """
        Updates package version specifier in requirements.txt content.
        Preserves comments, extras, markers, and comparison operators (==, >=, ~=, etc.).
        """
        # Pattern matching package with optional extras [security], operators, version, markers, comments
        pattern = re.compile(
            rf"^(\s*{re.escape(package_name)}(?:\[.*?\])?\s*)(==|>=|<=|~=|>|<|!=)?\s*([0-9a-zA-Z\.\-_*]+)?(\s*(?:;.*?|#.*)?)$",
            re.IGNORECASE | re.MULTILINE
        )

        match = pattern.search(content)
        if match:
            prefix = match.group(1).rstrip()
            op = ">="
            suffix = match.group(4) or ""
            
            # Format clean new line
            new_line = f"{prefix}{op}{target_version}{suffix}"
            new_content = pattern.sub(new_line, content, count=1)
            return new_content, True
        else:
            # Append if not found
            new_content = content.rstrip() + f"\n{package_name}>={target_version}\n"
            return new_content, True

    @staticmethod
    def patch_package_json(content: str, package_name: str, target_version: str) -> Tuple[str, bool]:
        """
        Updates dependency version inside package.json JSON content.
        Preserves prefix operators (~, >=) or defaults to ^ for modern NPM versioning.
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return content, False

        modified = False
        for section in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
            if section in data and package_name in data[section]:
                existing_val = str(data[section][package_name])
                prefix = "^"
                if existing_val.startswith("~"):
                    prefix = "~"
                elif existing_val.startswith(">="):
                    prefix = ">="

                data[section][package_name] = f"{prefix}{target_version}"
                modified = True

        if not modified:
            if "dependencies" not in data:
                data["dependencies"] = {}
            data["dependencies"][package_name] = f"^{target_version}"
            modified = True

        return json.dumps(data, indent=2) + "\n", modified
