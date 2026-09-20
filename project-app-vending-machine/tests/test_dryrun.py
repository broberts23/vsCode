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
    ca_policy = result["result"]["conditionalAccessPolicy"]
    assert "clientApplications" in ca_policy["conditions"]
    assert "ipRanges" not in ca_policy["conditions"]
    assert ca_policy["conditions"]["applications"]["includeApplications"] == ["All"]
    assert "_namedLocation" in ca_policy
    assert ca_policy["_namedLocation"]["ipRanges"][0]["cidrAddress"] == "10.0.0.0/8"


def test_privileged_payroll_api_dry_run():
    payload = {
        "offeringId": "privileged-payroll-api",
        "displayName": "Payroll API - Prod",
        "owners": ["33333333-3333-3333-3333-333333333333"],
        "justification": "REQ009001",
        "parameters": {},
    }
    result = process_vend_request(payload, request_id="test-payroll-001")

    assert result["status"] == "completed"
    assert result["offeringId"] == "privileged-payroll-api"

    dry_run = result["result"]["dryRunPlan"]
    optional_claims = dry_run["application"]["optionalClaims"]["accessToken"]
    assert any(claim["name"] == "xms_cc" for claim in optional_claims)
    assert dry_run["application"]["api"]["requestedAccessTokenVersion"] == 2

    ca_policy = result["result"]["conditionalAccessPolicy"]
    sif = ca_policy["sessionControls"]["signInFrequency"]
    assert sif["value"] == 1
    assert sif["type"] == "hours"
    # Graph 1138 rejects CAE strictEnforcement; SKU relies on app xms_cc + SIF.
    assert "continuousAccessEvaluation" not in ca_policy["sessionControls"]
    assert ca_policy["state"] == "enabled"
    assert any(role["value"] == "Payroll.Write" for role in result["result"]["appRoles"])
