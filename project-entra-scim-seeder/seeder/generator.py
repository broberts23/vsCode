"""Deterministic user profile generation using Faker."""

import os

from faker import Faker

fake = Faker()
fake.seed_instance(42)

DEPARTMENTS = [
    "Engineering",
    "Data Science",
    "Security",
    "DevOps",
    "Product",
    "Finance",
    "Human Resources",
    "Marketing",
]

JOB_TITLES = [
    "Lead AI Engineer",
    "Cloud Architect",
    "Security Analyst",
    "DevOps Engineer",
    "Product Manager",
    "Data Scientist",
    "SRE",
    "Platform Engineer",
    "Identity Engineer",
    "Software Developer",
]


def generate_synthetic_users(count: int) -> list[dict]:
    """Generate synthetic user payloads matching Graph /users creation schema.

    Args:
        count: Number of user profiles to generate.

    Returns:
        List of dicts with keys: accountEnabled, displayName, mailNickname,
        userPrincipalName, passwordProfile, jobTitle, department.
    """
    domain: str = os.environ.get("DOMAIN", "yourdomain.onmicrosoft.com")
    users: list[dict] = []

    for _ in range(count):
        first_name = fake.first_name()
        last_name = fake.last_name()
        display_name = f"{first_name} {last_name}"
        mail_nickname = f"{first_name[0]}{last_name}".lower()
        upn = f"{mail_nickname}@{domain}"

        users.append(
            {
                "accountEnabled": True,
                "displayName": display_name,
                "mailNickname": mail_nickname,
                "userPrincipalName": upn,
                "passwordProfile": {
                    "forceChangePasswordNextSignIn": False,
                    "password": "ComplexPassword123!",
                },
                "jobTitle": fake.random_element(JOB_TITLES),
                "department": fake.random_element(DEPARTMENTS),
            }
        )

    return users


def generate_synthetic_groups() -> list[dict]:
    """Return static security groups required for testing context.

    Returns:
        List of group dicts with displayName, mailEnabled, securityEnabled,
        and mailNickname keys.
    """
    return [
        {
            "displayName": "App-AI-Standard",
            "mailEnabled": False,
            "mailNickname": "app-ai-standard",
            "securityEnabled": True,
            "description": "Standard AI application access group",
        },
        {
            "displayName": "App-AI-Privileged",
            "mailEnabled": False,
            "mailNickname": "app-ai-privileged",
            "securityEnabled": True,
            "description": "Privileged AI application access group",
        },
        {
            "displayName": "Omit-AI-Access",
            "mailEnabled": False,
            "mailNickname": "omit-ai-access",
            "securityEnabled": True,
            "description": "Users explicitly excluded from AI access",
        },
    ]
