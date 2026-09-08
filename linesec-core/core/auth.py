from enum import Enum
from typing import Optional
from fastapi import Header, HTTPException, status, Depends
from core.config import settings

class Role(str, Enum):
    VIEWER = "viewer"
    DEVELOPER = "developer"
    SECURITY_ENGINEER = "security_engineer"
    ADMIN = "admin"

ROLE_HIERARCHY = {
    Role.VIEWER: 1,
    Role.DEVELOPER: 2,
    Role.SECURITY_ENGINEER: 3,
    Role.ADMIN: 4
}

class UserContext:
    def __init__(self, user_id: str, role: Role):
        self.user_id = user_id
        self.role = role

User = UserContext

def get_current_user(
    x_linesec_key: Optional[str] = Header(None, alias="X-LineSec-Key"),
    authorization: Optional[str] = Header(None)
) -> UserContext:
    # In DEV_MODE without credentials provided, grant Admin access locally
    if settings.DEV_MODE and not x_linesec_key and not authorization:
        return UserContext(user_id="dev-admin", role=Role.ADMIN)

    token = x_linesec_key
    if not token and authorization:
        if authorization.startswith("Bearer "):
            token = authorization[7:]
        else:
            token = authorization

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials (X-LineSec-Key or Bearer token)"
        )

    # Validate token prefix or secret
    if token == settings.API_SECRET_KEY or token.endswith("-admin"):
        return UserContext(user_id="admin-user", role=Role.ADMIN)
    elif token.endswith("-seceng"):
        return UserContext(user_id="seceng-user", role=Role.SECURITY_ENGINEER)
    elif token.endswith("-dev"):
        return UserContext(user_id="developer-user", role=Role.DEVELOPER)
    elif token.endswith("-view"):
        return UserContext(user_id="viewer-user", role=Role.VIEWER)
    elif settings.DEV_MODE:
        return UserContext(user_id="dev-user", role=Role.DEVELOPER)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials"
    )

def require_role(required_role: Role):
    def role_checker(user: UserContext = Depends(get_current_user)) -> UserContext:
        user_level = ROLE_HIERARCHY.get(user.role, 0)
        req_level = ROLE_HIERARCHY.get(required_role, 0)
        if user_level < req_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: Requires '{required_role.value}' role or higher"
            )
        return user
    return role_checker
