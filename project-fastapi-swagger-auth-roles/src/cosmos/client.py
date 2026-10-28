"""Cosmos DB client factory."""

from azure.cosmos import CosmosClient, PartitionKey
from azure.identity import DefaultAzureCredential

from src.config import Settings


def create_cosmos_client(settings: Settings) -> CosmosClient:
    if settings.use_cosmos_emulator:
        return CosmosClient(
            settings.cosmos_endpoint,
            credential=settings.cosmos_key,
            connection_verify=False,
            enable_endpoint_discovery=False,
        )
    if not settings.cosmos_endpoint:
        raise RuntimeError("COSMOS_ENDPOINT is required when not using the emulator")
    return CosmosClient(
        settings.cosmos_endpoint,
        credential=DefaultAzureCredential(),
    )


def ensure_identity_container(client: CosmosClient, settings: Settings):
    if settings.use_cosmos_emulator:
        database = client.create_database_if_not_exists(settings.cosmos_database)
        return database.create_container_if_not_exists(
            id=settings.cosmos_container,
            partition_key=PartitionKey(path="/id"),
        )
    # Azure: database/container are provisioned by Bicep; use existing resources.
    database = client.get_database_client(settings.cosmos_database)
    return database.get_container_client(settings.cosmos_container)
