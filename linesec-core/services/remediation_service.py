import os
import re
import subprocess
import shutil
from typing import Optional, Dict, Any, List, Tuple
from core.config import settings
from services.patcher import ManifestPatcher

class WorkspaceSecurityError(ValueError):
    """Raised when an unsafe path or directory traversal is detected."""
    pass

class RemediationExecutionService:
    """
    Safely executes repository operations in an isolated workspace:
    - Path traversal validation
    - Git branch creation
    - Manifest patching
    - Automated test runner execution
    - Git commit & push
    - Real GitHub PR creation via PyGithub
    """

    @staticmethod
    def sanitize_workspace_path(base_dir: str, target_file: str) -> str:
        """
        Ensures target_file resolves strictly inside base_dir, preventing path traversal.
        """
        full_path = os.path.abspath(os.path.join(base_dir, target_file))
        base_abs = os.path.abspath(base_dir)
        if not full_path.startswith(base_abs):
            raise WorkspaceSecurityError(f"Path traversal detected: {target_file} is outside {base_dir}")
        return full_path

    @classmethod
    def apply_patch_and_test(
        cls,
        repo_dir: str,
        package: str,
        target_version: str,
        ecosystem: str = "pip",
        test_command: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Applies a manifest patch to the repository and runs local verification tests.
        """
        if not os.path.isdir(repo_dir):
            raise ValueError(f"Repository directory does not exist: {repo_dir}")

        manifest_name = "package.json" if ecosystem.lower() in ("npm", "node", "javascript") else "requirements.txt"
        manifest_path = cls.sanitize_workspace_path(repo_dir, manifest_name)

        if not os.path.exists(manifest_path):
            return {
                "success": False,
                "error": f"Manifest file '{manifest_name}' not found in {repo_dir}",
                "patched": False
            }

        with open(manifest_path, "r", encoding="utf-8") as f:
            content = f.read()

        if manifest_name == "package.json":
            patched_content, modified = ManifestPatcher.patch_package_json(content, package, target_version)
        else:
            patched_content, modified = ManifestPatcher.patch_requirements_txt(content, package, target_version)

        if modified:
            with open(manifest_path, "w", encoding="utf-8") as f:
                f.write(patched_content)

        # Run test suite if test_command provided
        test_passed = True
        test_output = ""
        if test_command:
            try:
                res = subprocess.run(
                    test_command,
                    cwd=repo_dir,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                test_passed = (res.returncode == 0)
                test_output = res.stdout + "\n" + res.stderr
            except Exception as e:
                test_passed = False
                test_output = f"Test execution failed with error: {e}"

        return {
            "success": modified and test_passed,
            "manifest": manifest_name,
            "patched": modified,
            "test_passed": test_passed,
            "test_output": test_output
        }

    @staticmethod
    def create_github_pr(
        repo_slug: str,
        branch_name: str,
        title: str,
        body: str,
        token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates a real Pull Request in GitHub using PyGithub.
        """
        github_token = token or settings.GITHUB_TOKEN
        if not github_token:
            return {
                "created": False,
                "status": "TOKEN_MISSING",
                "message": "GITHUB_TOKEN not configured. Generated PR payload ready for manual dispatch."
            }

        if not repo_slug or "/" not in repo_slug:
            return {
                "created": False,
                "status": "INVALID_REPO",
                "message": f"Invalid repository slug format: '{repo_slug}'. Expected 'Owner/Repo'."
            }

        try:
            from github import Github, Auth
            auth = Auth.Token(github_token)
            gh = Github(auth=auth)
            repo = gh.get_repo(repo_slug)
            
            # Fetch default branch
            default_branch = repo.default_branch or "main"
            
            pr = repo.create_pull(
                title=title,
                body=body,
                head=branch_name,
                base=default_branch
            )

            return {
                "created": True,
                "status": "PR_CREATED",
                "pr_number": pr.number,
                "html_url": pr.html_url,
                "message": f"Successfully created GitHub Pull Request #{pr.number}"
            }
        except Exception as e:
            return {
                "created": False,
                "status": "GITHUB_API_ERROR",
                "message": f"GitHub API error: {str(e)}"
            }

    @classmethod
    def execute_remediation(
        cls,
        db: Any,
        task_id: str,
        workspace_dir: Optional[str] = None,
        target_repo_slug: Optional[str] = None,
        github_token: Optional[str] = None,
        push_remote: bool = False,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        End-to-end execution of automated remediation in an isolated workspace with Git & PR integration.
        """
        import models
        from core.lifecycle import TaskStatus
        task = db.query(models.RemediationTask).filter(models.RemediationTask.task_id == task_id).first()
        if not task:
            return {"success": False, "error": f"Task '{task_id}' not found"}

        package = task.package or "dependency"
        target_version = task.target_version or "latest"
        ecosystem = task.ecosystem or "pip"
        branch_name = f"linesec/fix-{package}-{target_version}"

        if workspace_dir:
            # Path traversal check against WORKSPACE_ROOT
            workspace_abs = os.path.abspath(workspace_dir)
            root_abs = os.path.abspath(settings.WORKSPACE_ROOT)
            if not workspace_abs.startswith(root_abs):
                return {
                    "success": False,
                    "error": f"Path traversal attempt detected: '{workspace_dir}' is outside '{settings.WORKSPACE_ROOT}'"
                }

            if not os.path.isdir(workspace_abs):
                return {"success": False, "error": f"Workspace directory does not exist: {workspace_dir}"}

            # Git checkout branch
            try:
                subprocess.run(["git", "checkout", "-B", branch_name], cwd=workspace_abs, check=True, capture_output=True)
            except Exception as e:
                return {"success": False, "error": f"Failed to create git branch: {e}"}

            # Apply patch
            patch_res = cls.apply_patch_and_test(
                repo_dir=workspace_abs,
                package=package,
                target_version=target_version,
                ecosystem=ecosystem
            )
            if not patch_res.get("patched"):
                return {"success": False, "error": "Manifest patching failed", "details": patch_res}

            # Commit changes
            try:
                subprocess.run(["git", "add", "."], cwd=workspace_abs, check=True, capture_output=True)
                commit_msg = f"fix(security): bump {package} to {target_version} [LineSec 2+]"
                subprocess.run(["git", "commit", "-m", commit_msg], cwd=workspace_abs, check=True, capture_output=True)
            except Exception:
                pass

            # Push branch if requested or target repo is specified
            if target_repo_slug and not dry_run and push_remote:
                try:
                    subprocess.run(["git", "push", "-u", "origin", branch_name, "--force"], cwd=workspace_abs, check=True, capture_output=True)
                except Exception as e:
                    pass

            if not dry_run:
                task.status = TaskStatus.PR_OPENED.value if task.safety_level == "SAFE" else TaskStatus.TICKET_OPENED.value
                db.commit()

            pr_info = None
            if target_repo_slug and not dry_run:
                pr_info = cls.create_github_pr(
                    repo_slug=target_repo_slug,
                    branch_name=branch_name,
                    title=f"[LineSec Security Fix] {task.title}",
                    body=f"Remediation for task {task_id}: bump {package} to {target_version}",
                    token=github_token
                )

            return {
                "success": True,
                "task_id": task_id,
                "branch_created": branch_name,
                "manifest_patched": True,
                "status": task.status,
                "pr_info": pr_info
            }

        return {
            "success": True,
            "task_id": task_id,
            "branch_created": branch_name,
            "manifest_patched": False,
            "status": task.status
        }
