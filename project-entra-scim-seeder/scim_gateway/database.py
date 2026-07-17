"""Azure Cosmos DB container management via azure-identity."""

import logging
import os

from azure.cosmos import CosmosClient, PartitionKey
from azure.identity import DefaultAzureCredential

logger = logging.getLogger(__name__)

COSMOS_ENDPOINT = os.environ.get("COSMOS_ENDPOINT", "")
COSMOS_DATABASE = os.environ.get("SCIM_COSMOS_DATABASE_NAME", "scim-db")
COSMOS_CONTAINER = os.environ.get("SCIM_COSMOS_CONTAINER_NAME", "users")
COSMOS_PARTITION_KEY = "/userName"


def get_cosmos_client() -> CosmosClient:
    """Initialize a keyless Cosmos Client using Managed Identity or Azure CLI."""
    if not COSMOS_ENDPOINT:
        raise RuntimeError("COSMOS_ENDPOINT environment variable is not set")
    credential = DefaultAzureCredential()
    return CosmosClient(url=COSMOS_ENDPOINT, credential=credential)


def init_db() -> None:
    """Create the Cosmos database and container if they do not exist."""
    client = get_cosmos_client()
    database = client.create_database_if_not_exists(id=COSMOS_DATABASE)
    database.create_container_if_not_exists(
        id=COSMOS_CONTAINER,
        partition_key=PartitionKey(path=COSMOS_PARTITION_KEY),
    )
    logger.info(
        "Cosmos DB initialized: db=%s container=%s", COSMOS_DATABASE, COSMOS_CONTAINER
    )


def get_container():
    """Return the Cosmos container client used for item CRUD."""
    client = get_cosmos_client()
    database = client.get_database_client(COSMOS_DATABASE)
    return database.get_container_client(COSMOS_CONTAINER)
