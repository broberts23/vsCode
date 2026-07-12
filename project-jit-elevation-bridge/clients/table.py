import os
import logging
from azure.data.tables import TableClient, TableServiceClient

logging.basicConfig(level=logging.INFO)
STORAGE_CONNECTION_STRING = os.getenv("AzureWebJobsStorage")
TABLE_NAME = os.getenv("TABLE_NAME", "jitaccesslogs")


def get_table_client() -> TableClient:
    table_client = TableClient.from_connection_string(
        conn_str=STORAGE_CONNECTION_STRING, table_name=TABLE_NAME)
    return table_client


def get_table_service_client() -> TableServiceClient:
    table_service_client = TableServiceClient.from_connection_string(
        conn_str=STORAGE_CONNECTION_STRING, table_name=TABLE_NAME)

    try:
        table_service_client.create_table_if_not_exists(table_name=TABLE_NAME)
    except Exception as e:
        logging.info(
            f"Table '{TABLE_NAME}' could not be created: {str(e)}")

    return table_service_client
