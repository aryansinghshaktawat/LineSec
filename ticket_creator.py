import os
from dotenv import load_dotenv
from github import Github, Auth
from sqlalchemy import create_engine, Column, String, Integer, Text
from sqlalchemy.orm import declarative_base, sessionmaker

# Load environment variables
load_dotenv()
github_token = os.getenv("GITHUB_TOKEN")
target_repo = os.getenv("TARGET_REPO")

if not github_token or not target_repo:
    raise ValueError("GITHUB_TOKEN and TARGET_REPO must be set in the .env file")

# Database connection
SQLALCHEMY_DATABASE_URL = "postgresql://localhost/linesec_core_db"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class Finding(Base):
    __tablename__ = "findings"

    finding_id = Column(String, primary_key=True, index=True)
    tool_name = Column(String, index=True)
    vulnerability_name = Column(String, index=True)
    severity = Column(String)
    description = Column(Text)
    file_path = Column(String)
    line_number = Column(Integer)
    remediation_status = Column(String, default="OPEN")
    root_cause = Column(Text, nullable=True)
    remediation_plan = Column(Text, nullable=True)

def create_tickets():
    db = SessionLocal()
    try:
        # Query findings with status 'ANALYZED'
        analyzed_findings = db.query(Finding).filter(Finding.remediation_status == 'ANALYZED').all()
        print(f"Found {len(analyzed_findings)} findings with status 'ANALYZED'.")

        if not analyzed_findings:
            return

        # Authenticate with GitHub using modern Auth token syntax
        auth = Auth.Token(github_token)
        g = Github(auth=auth)
        try:
            repo = g.get_repo(target_repo)
        except Exception as e:
            print(f"Failed to authenticate or connect to repo '{target_repo}': {e}")
            return

        for finding in analyzed_findings:
            title = f"[Security Alert] {finding.vulnerability_name}"
            
            body = (
                f"### Security Alert Details\n\n"
                f"* **Vulnerability Name:** {finding.vulnerability_name}\n"
                f"* **Severity:** {finding.severity}\n"
                f"* **File Path:** `{finding.file_path}`\n"
                f"* **Line Number:** {finding.line_number}\n"
                f"* **Detection Tool:** `{finding.tool_name}`\n\n"
                f"#### Description\n"
                f"{finding.description}\n\n"
                f"#### Root Cause\n"
                f"{finding.root_cause}\n\n"
                f"#### Remediation Plan\n"
                f"{finding.remediation_plan}\n"
            )

            print(f"Creating GitHub issue: '{title}'...")
            try:
                issue = repo.create_issue(title=title, body=body)
                print(f"Successfully created GitHub issue #{issue.number} for {finding.vulnerability_name}.")
                
                # Update status in DB
                finding.remediation_status = "TICKET_OPENED"
            except Exception as e:
                print(f"Failed to create GitHub issue for finding {finding.finding_id}: {e}")

        db.commit()
        print("Database commit successful.")
    finally:
        db.close()

if __name__ == "__main__":
    create_tickets()
