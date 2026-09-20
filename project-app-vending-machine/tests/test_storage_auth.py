from unittest.mock import MagicMock, patch

import pytest

from app_vending import settings, storage


@pytest.fixture(autouse=True)
def _clear_storage_env(monkeypatch):
    for key in (
        "AzureWebJobsStorage",
        "AzureWebJobsStorage__accountName",
        "STORAGE_ACCOUNT_NAME",
        "WORKER_CLIENT_ID",
        "AZURE_CLIENT_ID",
    ):
        monkeypatch.delenv(key, raising=False)
    storage._credential = None
    yield
    storage._credential = None


def test_uses_azurite_connection_string_by_default():
    assert settings.get_storage_connection_string() == "UseDevelopmentStorage=true"
    assert settings.uses_storage_connection_string() is True


def test_uses_explicit_account_key_connection_string(monkeypatch):
    monkeypatch.setenv(
        "AzureWebJobsStorage",
        "DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=abc;EndpointSuffix=core.windows.net",
    )
    assert settings.uses_storage_connection_string() is True


def test_identity_path_when_account_name_set(monkeypatch):
    monkeypatch.setenv("STORAGE_ACCOUNT_NAME", "appvendstdevabc123")
    assert settings.uses_storage_connection_string() is False
    assert settings.get_storage_account_name() == "appvendstdevabc123"
    assert settings.get_storage_connection_string() is None


def test_account_name_from_functions_identity_setting(monkeypatch):
    monkeypatch.setenv("AzureWebJobsStorage__accountName", "funcstorage")
    assert settings.get_storage_account_name() == "funcstorage"
    assert settings.uses_storage_connection_string() is False


def test_table_client_uses_connection_string_for_azurite(monkeypatch):
    monkeypatch.setenv("AzureWebJobsStorage", "UseDevelopmentStorage=true")
    with patch.object(storage.TableServiceClient, "from_connection_string") as mock_from_cs:
        mock_svc = MagicMock()
        mock_from_cs.return_value = mock_svc
        storage._table_client()
        mock_from_cs.assert_called_once_with("UseDevelopmentStorage=true")
        mock_svc.get_table_client.assert_called_once_with(settings.TABLE_NAME)


def test_table_client_uses_credential_for_identity(monkeypatch):
    monkeypatch.setenv("STORAGE_ACCOUNT_NAME", "appvendstdevxyz")
    fake_cred = object()
    with (
        patch.object(storage, "_get_credential", return_value=fake_cred),
        patch.object(storage, "TableServiceClient") as mock_tsc,
    ):
        mock_svc = MagicMock()
        mock_tsc.return_value = mock_svc
        storage._table_client()
        mock_tsc.assert_called_once_with(
            endpoint="https://appvendstdevxyz.table.core.windows.net",
            credential=fake_cred,
        )


def test_queue_client_uses_credential_for_identity(monkeypatch):
    monkeypatch.setenv("AzureWebJobsStorage__accountName", "appvendstdevxyz")
    fake_cred = object()
    with (
        patch.object(storage, "_get_credential", return_value=fake_cred),
        patch.object(storage, "QueueClient") as mock_qc,
    ):
        storage._queue_client()
        mock_qc.assert_called_once_with(
            account_url="https://appvendstdevxyz.queue.core.windows.net",
            queue_name=settings.QUEUE_NAME,
            credential=fake_cred,
        )


def test_worker_client_id_prefers_worker_over_azure(monkeypatch):
    monkeypatch.setenv("WORKER_CLIENT_ID", "worker-id")
    monkeypatch.setenv("AZURE_CLIENT_ID", "legacy-id")
    assert settings.get_worker_client_id() == "worker-id"


def test_worker_client_id_falls_back_to_azure_client_id(monkeypatch):
    monkeypatch.setenv("AZURE_CLIENT_ID", "legacy-id")
    assert settings.get_worker_client_id() == "legacy-id"
