"""MSAL client assertions & Graph SDK client initialization."""

import logging
import os

from azure.identity import ClientSecretCredential
from msgraph import GraphServiceClient

logger = logging.getLogger(__name__)


def get_graph_client() -> GraphServiceClient:
    """Read TENANT_ID, CLIENT_ID, CLIENT_SECRET from environment.

    Instantiate a ClientSecretCredential and pass it into the Microsoft
    Graph SDK GraphServiceClient.

    Returns:
        GraphServiceClient authenticated for https://graph.microsoft.com/.default.
    """
    tenant_id = os.environ["TENANT_ID"]
    client_id = os.environ["CLIENT_ID"]
    client_secret = os.environ["CLIENT_SECRET"]

    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )

    logger.info("GraphServiceClient initialized for tenant %s", tenant_id)
    return GraphServiceClient(credential, scopes=["https://graph.microsoft.com/.default"])
