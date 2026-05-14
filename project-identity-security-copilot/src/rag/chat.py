"""Grounded question answering for the Identity Security Copilot.

PowerShell bridge:
- This file is the orchestrator. It retrieves evidence, calls the model, and formats the result.
- The overall flow is similar to a PowerShell function that calls one service for lookup and another for reasoning.
"""

from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

from azure.search.documents.models import QueryType

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import AppConfig
from src.foundry.project_client import list_deployment_names, open_project_client
from src.search.service import create_search_client
from src.security.masking import mask_answer


def answer_question(prompt: str, settings: AppConfig | None = None) -> str:
    """Run the full grounded Q&A flow.

    PowerShell bridge:
    - Think of this as the top-level advanced function that coordinates the rest of the module.
    """

    active_settings = settings or AppConfig.from_env()
    search_results = search_documents(prompt, active_settings)
    answer = complete_with_foundry(prompt, search_results, active_settings)
    answer_with_citations = append_citations(answer, search_results)
    return mask_answer(answer_with_citations)


def search_documents(prompt: str, settings: AppConfig, top: int = 5) -> list[dict[str, Any]]:
    client = create_search_client(settings)
    results = client.search(
        search_text=prompt,
        query_type=QueryType.SEMANTIC,
        semantic_configuration_name='default',
        top=top,
        select=['id', 'source_type', 'title', 'content', 'file_path', 'heading', 'tags'],
    )

    documents: list[dict[str, Any]] = []
    for result in results:
        documents.append(
            {
                'id': result.get('id'),
                'source_type': result.get('source_type'),
                'title': result.get('title'),
                'content': result.get('content'),
                'file_path': result.get('file_path'),
                'heading': result.get('heading'),
                'tags': result.get('tags'),
            }
        )

    return documents


def complete_with_foundry(prompt: str, search_results: list[dict[str, Any]], settings: AppConfig) -> str:
    """Call the model deployment through the Azure AI Foundry project client."""

    grounded_context = format_grounding_context(search_results)
    deployments = set(list_deployment_names(settings))
    if settings.azure_ai_chat_deployment not in deployments:
        raise RuntimeError(
            f'Configured deployment {settings.azure_ai_chat_deployment} was not found in the Foundry project.'
        )

    with open_project_client(settings) as project_client, project_client.get_openai_client() as openai_client:
        response = openai_client.responses.create(
            model=settings.azure_ai_chat_deployment,
            instructions=(
                'You are an identity security copilot. Answer only from the grounded context provided. '
                'If the evidence is missing or incomplete, say that directly. '
                'When you use evidence, cite document IDs in square brackets.'
            ),
            input=f'Question:\n{prompt}\n\nGrounded context:\n{grounded_context}',
        )
        return response.output_text or 'No response text was returned by the model.'


def summarize_evidence(topic: str, settings: AppConfig | None = None) -> str:
    """Use the summary deployment for short evidence summaries.

    PowerShell bridge:
    - This function exists to show task-based model selection, even if a lab uses the same model for both tasks.
    """

    active_settings = settings or AppConfig.from_env()
    with open_project_client(active_settings) as project_client, project_client.get_openai_client() as openai_client:
        response = openai_client.responses.create(
            model=active_settings.azure_ai_summary_deployment,
            instructions='Summarize the topic in two short paragraphs for an identity security engineer.',
            input=topic,
        )
        return response.output_text or 'No summary text was returned by the model.'


def format_grounding_context(search_results: list[dict[str, Any]]) -> str:
    if not search_results:
        return 'No grounded documents were retrieved from Azure AI Search.'

    sections: list[str] = []
    for item in search_results:
        sections.append(
            '\n'.join(
                [
                    f"Document ID: {item.get('id')}",
                    f"Title: {item.get('title')}",
                    f"Heading: {item.get('heading')}",
                    f"File: {item.get('file_path')}",
                    f"Tags: {item.get('tags')}",
                    f"Content: {item.get('content')}",
                ]
            )
        )

    return '\n\n'.join(sections)


def append_citations(answer: str, search_results: list[dict[str, Any]]) -> str:
    citations = format_citations(search_results)
    if not citations:
        return answer

    separator = '\n\n' if answer.strip() else ''
    return f'{answer.rstrip()}{separator}Sources:\n{citations}'


def format_citations(search_results: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    seen_ids: set[str] = set()

    for item in search_results:
        document_id = str(item.get('id') or '').strip()
        if not document_id or document_id in seen_ids:
            continue

        seen_ids.add(document_id)
        lines.append(f"- {document_id} | {item.get('title')} | {item.get('file_path')}")

    return '\n'.join(lines)
