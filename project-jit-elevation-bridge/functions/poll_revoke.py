import json
import os
import logging

import azure.functions as func
from datetime import datetime, timedelta, timezone
from services.arc_orchestrator import ArcOrchestrator
from clients.table import get_table_service_client, get_table_client

logging.basicConfig(level=logging.INFO)
orchestrator = ArcOrchestrator()
table_service_client = get_table_service_client()
table_client = get_table_client()

bp = func.Blueprint()


@bp.timer_trigger(arg_name="mytimer", schedule="0 */5 * * * *", run_on_startup=False)
def poll_and_revoke_trigger(mytimer: func.TimerRequest) -> None:
    logging.info("Running cleanup of expired JIT requests.")
    current_time = datetime.now(timezone.utc)
    query = f"PartitionKey eq 'JitActiveList' and ExpirationTime le '{current_time.isoformat()}'"
    try:

        entities = table_client.query_entities(query_filter=query)
        for entity in entities:
            expiration_time_str = entity.get("ExpirationTime")
            dmsa_name = entity.get("DmsaName")
            target_group = entity.get("TargetGroup")

            logging.info(
                f"Revoking access for {dmsa_name} to {target_group} due to expiration at {expiration_time_str}.")

            try:
                orchestrator.execute_ad_change(
                    dmsa_name, target_group, "revoke")
                table_client.delete_entity(
                    partition_key=entity["PartitionKey"], row_key=entity["RowKey"])
                logging.info(
                    f"Successfully revoked access and removed database state for {dmsa_name}.")
            except Exception as e:
                logging.error(
                    f"Failed to revoke access for {dmsa_name} to {target_group}: {str(e)}")

    except Exception as e:
        logging.error(f"Failed to cleanup expired JIT requests: {str(e)}")
