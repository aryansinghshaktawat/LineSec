import json
import pytest
from services.patcher import ManifestPatcher

def test_patch_requirements_txt_existing_package():
    content = "requests==2.25.0\nflask>=1.1.0\nurllib3==1.26.4\n"
    patched, ok = ManifestPatcher.patch_requirements_txt(content, "requests", "2.31.0")
    assert ok is True
    assert "requests>=2.31.0" in patched
    assert "flask>=1.1.0" in patched
    assert "urllib3==1.26.4" in patched

def test_patch_requirements_txt_append_if_missing():
    content = "flask>=1.1.0\n"
    patched, ok = ManifestPatcher.patch_requirements_txt(content, "requests", "2.31.0")
    assert ok is True
    assert "requests>=2.31.0" in patched
    assert "flask>=1.1.0" in patched

def test_patch_package_json_existing_dependency():
    content = json.dumps({
        "name": "sample-app",
        "dependencies": {
            "express": "4.17.1",
            "lodash": "4.17.19"
        }
    }, indent=2)
    patched, ok = ManifestPatcher.patch_package_json(content, "lodash", "4.17.21")
    assert ok is True
    data = json.loads(patched)
    assert data["dependencies"]["lodash"] == "^4.17.21"
    assert data["dependencies"]["express"] == "4.17.1"

def test_patch_package_json_append_new_dependency():
    content = json.dumps({
        "name": "sample-app",
        "dependencies": {
            "express": "4.17.1"
        }
    }, indent=2)
    patched, ok = ManifestPatcher.patch_package_json(content, "axios", "1.6.0")
    assert ok is True
    data = json.loads(patched)
    assert data["dependencies"]["axios"] == "^1.6.0"
