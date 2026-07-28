from fastapi import APIRouter, Depends, HTTPException, status

from app_vending.auth import require_submitter_role
from app_vending.models import VendAcceptedResponse, VendRequestBody, VendStatusResponse
from app_vending.storage import enqueue_request, get_request, save_request

router = APIRouter(prefix="/v1/requests", tags=["requests"])


@router.post("", response_model=VendAcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
def create_vend_request(
    body: VendRequestBody,
    _claims: dict = Depends(require_submitter_role),
) -> VendAcceptedResponse:
    import uuid

    request_id = str(uuid.uuid4())
    payload = body.model_dump(mode="json")
    save_request(request_id, payload, status="accepted")
    enqueue_request(request_id)

    return VendAcceptedResponse(
        requestId=request_id,
        statusUrl=f"/v1/requests/{request_id}",
    )


@router.get("/{request_id}", response_model=VendStatusResponse)
def get_vend_request(
    request_id: str,
    _claims: dict = Depends(require_submitter_role),
) -> VendStatusResponse:
    record = get_request(request_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found.")

    return VendStatusResponse(
        requestId=record["requestId"],
        status=record["status"],
        offeringId=record.get("offeringId"),
        executionMode=record.get("executionMode"),
        result=record.get("result"),
        error=record.get("error"),
        createdAt=record.get("createdAt"),
        completedAt=record.get("completedAt"),
    )
