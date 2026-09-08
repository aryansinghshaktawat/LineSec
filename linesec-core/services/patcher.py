import re
import json
from typing import Optional, Tuple

class ManifestPatcher:
    """
    Safely modifies package manifests (requirements.txt, package.json)
    to update vulnerable package versions to target fixed versions.
    """

    @staticmethod
    def patch_requirements_txt(content: str, package_name: str, target_version: str) -> Tuple[str, bool]:
        """
        Updates package version specifier in requirements.txt content.
        Supports ==, >=, ~=, <=, and unpinned package lines.
        """
        pkg_pattern = re.compile(rf"^(\s*{re.escape(package_name)})([=><~^!].*|$)", re.IGNORECASE | re.MULTILINE)
        
        match = pkg_pattern.search(content)
        if match:
            # Replace line with package>=target_version
            new_line = f"{package_name}>={target_version}"
            new_content = pkg_pattern.sub(new_line, content)
            return new_content, True
        else:
            # Append if not found
            new_content = content.rstrip() + f"\n{package_name}>={target_version}\n"
            return new_content, True

    @staticmethod
    def patch_package_json(content: str, package_name: str, target_version: str) -> Tuple[str, bool]:
        """
        Updates dependency version inside package.json JSON content.
        """
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return content, False

        modified = False
        for section in ["dependencies", "devDependencies", "peerDependencies"]:
            if section in data and package_name in data[section]:
                data[section][package_name] = f"^{target_version}"
                modified = True

        if not modified:
            if "dependencies" not in data:
                data["dependencies"] = {}
            data["dependencies"][package_name] = f"^{target_version}"
            modified = True

        return json.dumps(data, indent=2) + "\n", modified
