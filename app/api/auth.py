from fastapi import APIRouter, Depends, Form, HTTPException

from ..security import (
    create_access_token,
    get_current_user,
    require_roles,
    verify_password,
    hash_password
)


router = APIRouter(
    prefix="/api/auth",
    tags=["Authentication"]
)


# ============================================================
# DEVELOPMENT USERS
# ============================================================

USERS = {
    "admin": {
        "username": "admin",
        "password_hash": hash_password("Admin@12345"),
        "role": "ADMIN"
    },

    "analyst": {
        "username": "analyst",
        "password_hash": hash_password("Analyst@12345"),
        "role": "SOC_ANALYST"
    },

    "viewer": {
        "username": "viewer",
        "password_hash": hash_password("Viewer@12345"),
        "role": "VIEWER"
    }
}


# ============================================================
# LOGIN
# ============================================================

@router.post("/login")
def login(
    username: str = Form(...),
    password: str = Form(...)
):

    user = USERS.get(username)

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if not verify_password(
        password,
        user["password_hash"]
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    access_token = create_access_token(
        username=user["username"],
        role=user["role"]
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in_minutes": 60,
        "user": {
            "username": user["username"],
            "role": user["role"]
        }
    }


# ============================================================
# CURRENT USER
# ============================================================

@router.get("/me")
def get_me(
    current_user: dict = Depends(
        get_current_user
    )
):

    return {
        "authenticated": True,
        "username": current_user["username"],
        "role": current_user["role"]
    }


# ============================================================
# ADMIN TEST
# ============================================================

@router.get("/admin-test")
def admin_test(
    current_user: dict = Depends(
        require_roles("ADMIN")
    )
):

    return {
        "message": "Admin access granted",
        "user": current_user
    }


# ============================================================
# SOC ANALYST TEST
# ============================================================

@router.get("/analyst-test")
def analyst_test(
    current_user: dict = Depends(
        require_roles(
            "ADMIN",
            "SOC_ANALYST"
        )
    )
):

    return {
        "message": "SOC analyst access granted",
        "user": current_user
    }


# ============================================================
# VIEWER TEST
# ============================================================

@router.get("/viewer-test")
def viewer_test(
    current_user: dict = Depends(
        require_roles(
            "ADMIN",
            "SOC_ANALYST",
            "VIEWER"
        )
    )
):

    return {
        "message": "Authenticated viewer access granted",
        "user": current_user
    }