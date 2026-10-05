"""Cosmos DB client factory."""

from azure.cosmos import CosmosClient, PartitionKey

from src.config import Settings


def create_cosmos_client(settings: Settings) -> CosmosClient:
    if settings.use_cosmos_emulator:
        return CosmosClient(
            settings.cosmos_endpoint,
            credential=settings.cosmos_key,
            connection_verify=False,
            enable_endpoint_discovery=False,
        )
    return CosmosClient(settings.cosmos_endpoint, credential=settings.cosmos_key)


def ensure_identity_container(client: CosmosClient, settings: Settings):
    database = client.create_database_if_not_exists(settings.cosmos_database)
    return database.create_container_if_not_exists(
        id=settings.cosmos_container,
        partition_key=PartitionKey(path="/id"),
    )
