from app_vending.vend_execute import process_vend_request


def test_internal_hr_spa_dry_run():
    payload = {
        "offeringId": "internal-hr-spa",
        "displayName": "HR Internal Portal - Prod",
        "owners": ["11111111-1111-1111-1111-111111111111"],
        "justification": "ServiceNow REQ001234",
        "parameters": {},
    }
    result = process_vend_request(payload, request_id="test-hr-001")

    assert result["status"] == "completed"
    assert result["offeringId"] == "internal-hr-spa"
    assert result["result"]["dryRunPlan"] is not None
    assert any(role["value"] == "HR.Read" for role in result["result"]["appRoles"])


def test_aks_graph_workload_dry_run():
    payload = {
        "offeringId": "aks-graph-workload",
        "displayName": "AKS Order Service",
        "owners": ["22222222-2222-2222-2222-222222222222"],
        "justification": "REQ005678",
        "parameters": {
            "aksServiceAccount": "system:serviceaccount:orders:order-api",
            "allowedIpRanges": "10.0.0.0/8",
        },
    }
    result = process_vend_request(payload, request_id="test-aks-001")

    assert result["status"] == "completed"
    assert "utcmMonitorArtifact" in result["result"]
