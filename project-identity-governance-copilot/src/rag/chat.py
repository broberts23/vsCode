"""Cloud-backed retrieval and answer generation for the lab.

PowerShell bridge:
- This module is similar to an orchestration script that calls one service for lookup and another for generation.
- `list[dict[str, Any]]` is a typed list of dictionaries.
- `-> str` on a function means the function is expected to return a string.
- Helper names that begin with `_` are a convention for "private to this module", not strict access control.
"""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any, cast

from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from azure.search.documents.models import QueryType
from openai import AzureOpenAI


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.search.service import create_search_client
from src.security.masking import mask_answer


OPENAI_SCOPE = "https://cognitiveservices.azure.com/.default"


def answer_question(prompt: str) -> str:
    # Keep orchestration shallow: retrieve documents, ask the model, then append deterministic sources.
    search_results = search_documents(prompt)
    answer = complete_with_openai(prompt, search_results)
    answer_with_citations = append_citations(answer, search_results)
    return mask_answer(answer_with_citations)


def search_documents(prompt: str, top: int = 5) -> list[dict[str, Any]]:
    # The SearchClient is the Python equivalent of an SDK client object you would keep in a variable in PowerShell.
    client = create_search_client()
    results = client.search(
        search_text=prompt,
        query_type=QueryType.SEMANTIC,
        semantic_configuration_name="default",
        top=top,
        select=["id", "source_type", "title", "content", "principal_id", "severity"],
    )

    documents: list[dict[str, Any]] = []
    for result in results:
        # Azure SDK result items act like dictionaries, so `.get()` works the same way it does on a normal dict.
        documents.append(
            {
                "id": result.get("id"),
                "source_type": result.get("source_type"),
                "title": result.get("title"),
                "content": result.get("content"),
                "principal_id": result.get("principal_id"),
                "severity": result.get("severity"),
            }
        )

    return documents


def complete_with_openai(prompt: str, search_results: list[dict[str, Any]]) -> str:
    # `_get_required_env()` fails fast the same way a guard clause would in a PowerShell advanced function.
    endpoint = _get_required_env("AZURE_OPENAI_ENDPOINT")
    deployment = _get_required_env("AZURE_OPENAI_CHAT_DEPLOYMENT")
    api_version = _get_env("AZURE_OPENAI_API_VERSION", "2024-10-21")

    # `DefaultAzureCredential()` tries several auth sources in order, similar to a smart credential chain.
    credential = DefaultAzureCredential()
    token_provider = get_bearer_token_provider(credential, OPENAI_SCOPE)
    client = AzureOpenAI(
        azure_endpoint=endpoint,
        azure_ad_token_provider=token_provider,
        api_version=api_version,
    )

    grounded_context = _format_grounding_context(search_results)
    response = client.chat.completions.create(
        model=deployment,
        temperature=0.1,
        # The message list is like passing an ordered array of hashtables to define conversation state.
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an identity governance assistant. Answer only from the grounded context provided. "
                    "If the context is insufficient, say that directly and do not invent facts. "
                    "When you reference evidence, cite the source document IDs inline in square brackets, "
                    "for example [access-review-001]."
                ),
            },
            {
                "role": "user",
                "content": f"Question:\n{prompt}\n\nGrounded context:\n{grounded_context}",
            },
        ],
    )

    content = response.choices[0].message.content
    if isinstance(content, str):
        return content

    if not content:
        return "No completion content was returned by Azure OpenAI."

    # Some SDK responses can return structured content parts instead of one plain string.
    content_parts = cast(list[Any], content)
    return "".join(str(getattr(part, "text", "")) for part in content_parts if getattr(part, "type", None) == "text")


def _format_grounding_context(search_results: list[dict[str, Any]]) -> str:
    if not search_results:
        return "No grounded documents were retrieved from Azure AI Search."

    sections: list[str] = []
    for item in search_results:
        sections.append(
            "\n".join(
                [
                    f"Document ID: {item.get('id')}",
                    f"Type: {item.get('source_type')}",
                    f"Title: {item.get('title')}",
                    f"Principal ID: {item.get('principal_id')}",
                    f"Severity: {item.get('severity')}",
                    f"Content: {item.get('content')}",
                ]
            )
        )

    return "\n\n".join(sections)


def append_citations(answer: str, search_results: list[dict[str, Any]]) -> str:
    # We append a verified source list in code so attribution does not rely only on model behavior.
    citations = _format_citations(search_results)
    if not citations:
        return answer

    separator = "\n\n" if answer.strip() else ""
    return f"{answer.rstrip()}{separator}Sources:\n{citations}"


def _format_citations(search_results: list[dict[str, Any]]) -> str:
    if not search_results:
        return ""

    lines: list[str] = []
    seen_ids: set[str] = set()
    for item in search_results:
        # `set()` gives cheap duplicate detection, similar to tracking keys in a hash set.
        document_id = str(item.get("id") or "").strip()
        if not document_id or document_id in seen_ids:
            continue

        seen_ids.add(document_id)
        source_type = str(item.get("source_type") or "unknown")
        title = str(item.get("title") or "Untitled document")
        lines.append(f"- {document_id} | {source_type} | {title}")

    return "\n".join(lines)


def _get_required_env(name: str) -> str:
    value = _get_env(name)
    if not value:
        raise RuntimeError(f"{name} is required.")
    return value


def _get_env(name: str, default: str | None = None) -> str | None:
    import os

    # Returning `None` here is normal Python practice for "not found" when no default is supplied.
    return os.environ.get(name, default)