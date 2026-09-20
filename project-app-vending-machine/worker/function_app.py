import json
import logging

import azure.functions as func

from app_vending.callback import send_callback
from app_vending.settings import get_execution_mode
from app_vending.storage import get_request, get_request_payload, update_request
from app_vending.vend_execute import process_vend_request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = func.FunctionApp()


@app.queue_trigger(arg_name="msg", queue_name="vend-jobs", connection="AzureWebJobsStorage")
def process_vend_job(msg: func.QueueMessage) -> None:
    request_id = "unknown"
    payload_raw = None
    try:
        message = json.loads(msg.get_body().decode("utf-8"))
        request_id = message["requestId"]
        logger.info("Processing vend job %s", request_id)

        record = get_request(request_id)
        if not record:
            logger.error("Request %s was not found in table storage.", request_id)
            return

        payload_raw = get_request_payload(request_id)
        if not payload_raw:
            update_request(request_id, status="failed", error="Request payload was not found.")
            return

        outcome = process_vend_request(payload_raw, request_id=request_id)
        update_request(
            request_id,
            status=outcome["status"],
            result=outcome["result"],
            execution_mode=outcome["executionMode"],
        )

        callback_url = payload_raw.get("callbackUrl")
        if callback_url:
            send_callback(
                callback_url,
                {
                    "requestId": request_id,
                    "status": outcome["status"],
                    "offeringId": outcome["offeringId"],
                    "executionMode": outcome["executionMode"],
                    "result": outcome["result"],
                },
                callback_secret=payload_raw.get("callbackSecret"),
            )
    except Exception as exc:
        logger.exception("Vend job %s failed", request_id)
        execution_mode = get_execution_mode()
        try:
            update_request(
                request_id,
                status="failed",
                error=str(exc),
                execution_mode=execution_mode,
            )
        except Exception:
            logger.exception("Failed to persist failed status for %s", request_id)
        callback_url = payload_raw.get("callbackUrl") if payload_raw else None
        if callback_url:
            send_callback(
                callback_url,
                {
                    "requestId": request_id,
                    "status": "failed",
                    "offeringId": payload_raw.get("offeringId", "unknown"),
                    "executionMode": execution_mode,
                    "error": str(exc),
                },
                callback_secret=payload_raw.get("callbackSecret") if payload_raw else None,
            )
