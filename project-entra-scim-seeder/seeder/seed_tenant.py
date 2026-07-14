"""Directory seeding pipeline engine.

Creates users, creates groups, then binds memberships via $ref.
"""

import asyncio
import logging
import os

from dotenv import load_dotenv
from msgraph import GraphServiceClient
from msgraph.generated.models.user import User
from msgraph.generated.models.password_profile import PasswordProfile
from msgraph.generated.models.group import Group
from msgraph.generated.models.reference_create import ReferenceCreate

from seeder.auth import get_graph_client
from seeder.generator import generate_synthetic_users, generate_synthetic_groups

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger(__name__)


async def create_users_batch(
    client: GraphServiceClient, users: list[dict]
) -> dict[str, str]:
    """Provision users in Entra ID and return mailNickname -> Object GUID map.

    Args:
        client: Authenticated GraphServiceClient.
        users: List of user payload dicts from generator.

    Returns:
        Mapping of mailNickname to Entra User Object ID.
    """
    user_map: dict[str, str] = {}

    for payload in users:
        password_profile = PasswordProfile(
            password=payload["passwordProfile"]["password"],
            force_change_password_next_sign_in=payload["passwordProfile"][
                "forceChangePasswordNextSignIn"
            ],
        )

        user_obj = User(
            account_enabled=payload["accountEnabled"],
            display_name=payload["displayName"],
            mail_nickname=payload["mailNickname"],
            user_principal_name=payload["userPrincipalName"],
            password_profile=password_profile,
            job_title=payload["jobTitle"],
            department=payload["department"],
        )

        try:
            created = await client.users.post(user_obj)
            user_map[payload["mailNickname"]] = created.id
            logger.info("Created user: %s (%s)", payload["mailNickname"], created.id)
        except Exception:
            logger.exception("Failed to create user: %s", payload["mailNickname"])

    return user_map


async def create_groups_batch(
    client: GraphServiceClient, groups: list[dict]
) -> dict[str, str]:
    """Provision security groups in Entra ID and return displayName -> Group GUID map.

    Args:
        client: Authenticated GraphServiceClient.
        groups: List of group payload dicts from generator.

    Returns:
        Mapping of group displayName to Entra Group Object ID.
    """
    group_map: dict[str, str] = {}

    for payload in groups:
        group_obj = Group(
            display_name=payload["displayName"],
            mail_enabled=payload["mailEnabled"],
            mail_nickname=payload["mailNickname"],
            security_enabled=payload["securityEnabled"],
            description=payload.get("description"),
        )

        try:
            created = await client.groups.post(group_obj)
            group_map[payload["displayName"]] = created.id
            logger.info("Created group: %s (%s)", payload["displayName"], created.id)
        except Exception:
            logger.exception("Failed to create group: %s", payload["displayName"])

    return group_map


async def assign_users_to_groups(
    client: GraphServiceClient,
    user_map: dict[str, str],
    group_map: dict[str, str],
    users: list[dict],
) -> None:
    """Bind users to groups via the $ref membership endpoint.

    Assignment logic:
    - Data Science / Engineering users -> App-AI-Standard
    - Lead AI Engineer / Cloud Architect -> App-AI-Privileged
    - Remaining users -> Omit-AI-Access

    Args:
        client: Authenticated GraphServiceClient.
        user_map: mailNickname -> User Object ID.
        group_map: displayName -> Group Object ID.
        users: Original user payload list (for department/jobTitle lookup).
    """
    graph_base = "https://graph.microsoft.com/v1.0/directoryObjects"

    assignment_rules: dict[str, list[str]] = {
        "App-AI-Standard": ["Data Science", "Engineering"],
        "App-AI-Privileged": [],
        "Omit-AI-Access": [],
    }
    privileged_titles = {"Lead AI Engineer", "Cloud Architect"}

    for user_payload in users:
        nickname = user_payload["mailNickname"]
        user_id = user_map.get(nickname)
        if not user_id:
            continue

        department = user_payload["department"]
        job_title = user_payload["jobTitle"]

        if job_title in privileged_titles:
            target_group = "App-AI-Privileged"
        elif department in assignment_rules["App-AI-Standard"]:
            target_group = "App-AI-Standard"
        else:
            target_group = "Omit-AI-Access"

        group_id = group_map.get(target_group)
        if not group_id:
            logger.warning("Target group %s not found, skipping %s", target_group, nickname)
            continue

        ref_body = ReferenceCreate(
            odata_id=f"{graph_base}/{user_id}",
        )

        try:
            await client.groups.by_group_id(group_id).members.ref.post(ref_body)
            logger.info("Assigned %s -> %s", nickname, target_group)
        except Exception:
            logger.exception("Failed to assign %s to %s", nickname, target_group)


async def seed_tenant(user_count: int = 100) -> None:
    """Execute the full directory seeding pipeline.

    1. Generate and create users.
    2. Generate and create groups.
    3. Bind users to groups via $ref.
    """
    load_dotenv()

    client = get_graph_client()

    logger.info("Generating %d synthetic users...", user_count)
    users = generate_synthetic_users(user_count)

    logger.info("Creating users in Entra ID...")
    user_map = await create_users_batch(client, users)
    logger.info("Created %d/%d users", len(user_map), len(users))

    logger.info("Generating security groups...")
    groups = generate_synthetic_groups()

    logger.info("Creating groups in Entra ID...")
    group_map = await create_groups_batch(client, groups)
    logger.info("Created %d/%d groups", len(group_map), len(groups))

    logger.info("Assigning users to groups...")
    await assign_users_to_groups(client, user_map, group_map, users)

    logger.info("Seeding complete.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Seed Entra ID tenant")
    parser.add_argument("--users", type=int, default=100, help="Number of users to create")
    args = parser.parse_args()

    asyncio.run(seed_tenant(user_count=args.users))
