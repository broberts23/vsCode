import os
import logging
from azure.data.tables import TableServiceClient

logging.basicConfig(level=logging.INFO)

def get_table_service_client() -> TableServiceClient:
    STORAGE_CONNECTION_STRING = os.getenv("AzureWebJobsStorage")
    TABLE_NAME = os.getenv("TABLE_NAME", "jit_access_logs")

    table_service_client = TableServiceClient.from_connection_string(
        conn_str=STORAGE_CONNECTION_STRING, table_name=TABLE_NAME)

    try:
        table_service_client.create_table()
    except Exception as e:
        logging.info(
            f"Table '{TABLE_NAME}' already exists or could not be created: {str(e)}")

    return table_service_client