"""MailSentra Administrative Command Line Interface.

Provides out-of-band administrative provisioning and management utilities.
Usage:
    python -m app.cli create-admin --email admin@example.com --password StrongPassword2026!
"""

import argparse
import asyncio
import sys
from typing import Optional
from sqlalchemy import select
from app.core.security import get_password_hash
from app.db.base import Base
from app.db.session import async_engine, AsyncSessionLocal
from app.models.user import User, UserRole

KNOWN_INSECURE_PASSWORDS = {
    "MailSentraAdmin2026!",
    "Admin2026!",
    "admin",
    "password",
    "Password123!",
    "12345678",
    "admin123",
}


def validate_password_complexity(password: str) -> None:
    """Enforces strict password criteria for administrative accounts."""
    if len(password) < 12:
        raise ValueError("Administrative password must be at least 12 characters long.")
    if password in KNOWN_INSECURE_PASSWORDS:
        raise ValueError("Specified password matches a known insecure/default password. Please choose a unique credential.")


async def create_or_update_admin(
    email: str,
    password: str,
    full_name: Optional[str] = None,
    role: UserRole = UserRole.SUPER_ADMIN,
) -> bool:
    """Creates a new administrator account or securely updates an existing administrator's password."""
    validate_password_complexity(password)

    # Ensure tables exist
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        stmt = select(User).where(User.email == email)
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()

        hashed_pwd = get_password_hash(password)

        if user:
            user.hashed_password = hashed_pwd
            user.role = role
            user.is_active = True
            if full_name:
                user.full_name = full_name
            await session.commit()
            print(f"[SUCCESS] Updated existing administrator account: {email} (Role: {role.value})")
            return True
        else:
            new_user = User(
                email=email,
                full_name=full_name or "MailSentra Administrator",
                hashed_password=hashed_pwd,
                role=role,
                is_active=True,
            )
            session.add(new_user)
            await session.commit()
            print(f"[SUCCESS] Successfully provisioned administrator account: {email} (Role: {role.value})")
            return True


def main():
    parser = argparse.ArgumentParser(description="MailSentra Administrative CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # create-admin subcommand
    create_parser = subparsers.add_parser("create-admin", help="Provision a new Super Admin account")
    create_parser.add_argument("--email", required=True, help="Administrator email address")
    create_parser.add_argument("--password", required=True, help="Secure password (minimum 12 characters)")
    create_parser.add_argument("--full-name", default="MailSentra System Administrator", help="Full name of administrator")
    create_parser.add_argument("--role", default="SUPER_ADMIN", choices=["SUPER_ADMIN", "SOC_ANALYST", "AUDITOR"], help="User role")

    args = parser.parse_args()

    if args.command == "create-admin":
        try:
            role = UserRole[args.role]
            asyncio.run(create_or_update_admin(
                email=args.email.strip(),
                password=args.password,
                full_name=args.full_name,
                role=role,
            ))
        except ValueError as e:
            print(f"[ERROR] Security validation failed: {str(e)}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Failed to provision administrator: {str(e)}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
