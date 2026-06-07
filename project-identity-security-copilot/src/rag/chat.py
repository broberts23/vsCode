"""Grounded question answering for the Identity Security Copilot.

PowerShell bridge:
- This file is the orchestrator. It retrieves evidence, calls the model, and formats
    the result.
- The overall flow is similar to a PowerShell function that calls one service for
    lookup and another for reasoning.
- The module is intentionally procedural so the data flow reads top to bottom like a
    script, even though the implementation uses reusable helper functions.
"""

from __future__ import annotations
from dataclasses import dataclass
from src.security.masking import mask_answer
from src.search.service import create_search_client
from src.foundry.project_client import list_deployment_names, open_project_client
from src.config import AppConfig

import json
from pathlib import Path
import sys
from typing import Any

from azure.search.documents.models import QueryType

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@dataclass(slots=True)
class CopilotPlan:
    """Small request plan for the copilot.

    PowerShell bridge:
    - Think of this like a small object returned from a routing function before the main
        body decides which branch to run.
    - The plan keeps task selection explicit instead of burying it in one large block
        of control flow.
    """

    operation: str
    retrieval_query: str
    use_tools: bool


def route_request(prompt: str, settings: AppConfig | None = None) -> str:
    """Route the request to the best local copilot workflow.

    PowerShell bridge:
    - This is similar to a dispatcher function that picks a downstream command based on
        the intent of the incoming request.
    - The goal is not to be magically smart, but to keep the task split explicit:
        summary requests go to the summary deployment and grounded questions stay in the
        retrieval plus chat path.
    """

    plan = build_copilot_plan(prompt)
    active_settings = settings or AppConfig.from_env()

    if plan.operation == 'summarize':
        return summarize_evidence(plan.retrieval_query, active_settings)

    return answer_question(plan.retrieval_query, active_settings, use_tools=plan.use_tools)


def build_copilot_plan(prompt: str) -> CopilotPlan:
    """Choose the task path that best matches the request.

    PowerShell bridge:
    - This is like a lightweight `switch` statement that returns a small plan object.
    - The heuristic stays intentionally simple so the behavior is easy to reason about
        and easy to test.
    """

    normalized_prompt = ' '.join(prompt.split())
    lowered_prompt = normalized_prompt.lower()
    summary_prefixes = ('summarize', 'summary',
                        'give me a summary', 'provide a summary')
    summary_keywords = ('brief', 'overview', 'executive summary', 'key points')

    if lowered_prompt.startswith(summary_prefixes) or any(keyword in lowered_prompt for keyword in summary_keywords):
        return CopilotPlan(
            operation='summarize',
            retrieval_query=normalized_prompt,
            use_tools=False,
        )

    return CopilotPlan(
        operation='answer',
        retrieval_query=normalized_prompt,
        use_tools=True,
    )


def answer_question(prompt: str, settings: AppConfig | None = None, use_tools: bool = False) -> str:
    """Run the full grounded Q&A flow.

    PowerShell bridge:
        - Think of this as the top-level advanced function that coordinates the rest of
            the module.
        - The `settings` argument is optional so the function can be used from scripts,
            tests, or other callers without duplicating environment loading.
    """

    # Use caller-supplied settings when available, otherwise build them from the
    # environment just like a script would.
    active_settings = settings or AppConfig.from_env()
    search_results = search_documents(prompt, active_settings)
    answer, evidence_results = complete_with_foundry(
        prompt,
        search_results,
        active_settings,
        use_tools=use_tools,
    )
    answer_with_citations = append_citations(answer, evidence_results)
    return mask_answer(answer_with_citations)


def search_documents(prompt: str, settings: AppConfig, top: int = 5) -> list[dict[str, Any]]:
    """Run semantic search against the identity security knowledge base.

    PowerShell bridge:
    - This is the lookup step in the pipeline, similar to querying a service and
        reshaping the results into a simpler list.
    - Returning plain dictionaries keeps the downstream formatting logic simple.
    """

    client = create_search_client(settings)
    results = client.search(
        search_text=prompt,
        query_type=QueryType.SEMANTIC,
        semantic_configuration_name='default',
        top=top,
        select=['id', 'source_type', 'title',
                'content', 'file_path', 'heading', 'tags'],
    )

    documents: list[dict[str, Any]] = []
    for result in results:
        # Result objects from the SDK behave like lightweight records, so we normalize
        # them into plain dictionaries for later formatting.
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


def complete_with_foundry(
    prompt: str,
    search_results: list[dict[str, Any]],
    settings: AppConfig,
    use_tools: bool = False,
) -> tuple[str, list[dict[str, Any]]]:
    """Call the model deployment through the Azure AI Foundry project client.

    PowerShell bridge:
    - This is the reasoning step after retrieval.
    - The function validates that the configured deployment exists before asking the
      model to answer, which is the Python equivalent of a preflight guard clause.
    """

    grounded_context = format_grounding_context(search_results)
    deployments = set(list_deployment_names(settings))
    if settings.azure_ai_chat_deployment not in deployments:
        raise RuntimeError(
            f'Configured deployment {settings.azure_ai_chat_deployment} was not found in the Foundry project.'
        )

    # We open the project client and the OpenAI-compatible client in the same block so
    # the resources are always cleaned up when the request completes.
    with open_project_client(settings) as project_client, project_client.get_openai_client() as openai_client:
        if use_tools:
            return complete_with_tools(
                prompt,
                grounded_context,
                search_results,
                settings,
                openai_client,
            )

        response = openai_client.responses.create(
            model=settings.azure_ai_chat_deployment,
            instructions=(
                'You are an identity security copilot. Answer only from the grounded context provided. '
                'If the evidence is missing or incomplete, say that directly. '
                'When you use evidence, cite document IDs in square brackets.'
            ),
            input=f'Question:\n{prompt}\n\nGrounded context:\n{grounded_context}',
        )
        return response.output_text or 'No response text was returned by the model.', search_results


def complete_with_tools(
    prompt: str,
    grounded_context: str,
    initial_results: list[dict[str, Any]],
    settings: AppConfig,
    openai_client: Any,
) -> tuple[str, list[dict[str, Any]]]:
    """Let the chat deployment call small read-only tools before answering.

    PowerShell bridge:
    - Think of this as a short orchestration loop where the model can request an extra
      lookup, then continue once the lookup result is injected back into the workflow.
    - The tools are intentionally read-only and local to this process so the security
      boundary remains narrow and predictable.
    """

    response = openai_client.responses.create(
        model=settings.azure_ai_chat_deployment,
        instructions=(
            'You are an identity security copilot. Use the available read-only tools when '
            'you need more evidence, but answer only from the grounded context and tool outputs. '
            'If the evidence is missing or incomplete, say that directly. '
            'When you use evidence, cite document IDs in square brackets.'
        ),
        tools=build_foundry_tools(),
        input=(
            f'Question:\n{prompt}\n\n'
            f'Initial grounded context:\n{grounded_context}\n\n'
            'You may call a read-only search tool if you need better evidence or a narrower lookup.'
        ),
    )

    evidence_results = list(initial_results)
    for _ in range(3):
        function_calls = extract_function_calls(response)
        if not function_calls:
            return response.output_text or 'No response text was returned by the model.', evidence_results

        tool_outputs: list[dict[str, str]] = []
        for call in function_calls:
            tool_result, discovered_results = run_tool_call(call, settings)
            evidence_results.extend(discovered_results)
            tool_outputs.append(
                {
                    'type': 'function_call_output',
                    'call_id': str(call.get('call_id', '')),
                    'output': json.dumps(tool_result),
                }
            )

        response = openai_client.responses.create(
            model=settings.azure_ai_chat_deployment,
            previous_response_id=response.id,
            input=tool_outputs,
        )

    return response.output_text or 'No response text was returned by the model.', evidence_results


def build_foundry_tools() -> list[dict[str, Any]]:
    """Describe the read-only tools exposed to the chat deployment."""

    return [
        {
            'type': 'function',
            'name': 'search_identity_knowledge',
            'description': 'Search the identity security markdown knowledge base for grounded evidence.',
            'parameters': {
                'type': 'object',
                'properties': {
                    'query': {
                        'type': 'string',
                        'description': 'The identity security question or topic to search for.',
                    },
                    'top': {
                        'type': 'integer',
                        'description': 'How many grounded documents to return.',
                        'minimum': 1,
                        'maximum': 8,
                    },
                },
                'required': ['query'],
                'additionalProperties': False,
            },
        },
        {
            'type': 'function',
            'name': 'list_foundry_deployments',
            'description': 'List model deployments available through the current Foundry project.',
            'parameters': {
                'type': 'object',
                'properties': {},
                'additionalProperties': False,
            },
        },
    ]


def extract_function_calls(response: Any) -> list[dict[str, Any]]:
    """Normalize function calls from a Responses API object into plain dictionaries."""

    calls: list[dict[str, Any]] = []
    for item in getattr(response, 'output', []) or []:
        if getattr(item, 'type', None) != 'function_call':
            continue

        calls.append(
            {
                'name': getattr(item, 'name', ''),
                'arguments': getattr(item, 'arguments', '{}'),
                'call_id': getattr(item, 'call_id', ''),
            }
        )

    return calls


def run_tool_call(call: dict[str, Any], settings: AppConfig) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Execute one read-only tool call from the chat deployment."""

    tool_name = str(call.get('name', ''))
    raw_arguments = str(call.get('arguments', '{}') or '{}')
    arguments = json.loads(raw_arguments)

    if tool_name == 'search_identity_knowledge':
        query = str(arguments.get('query', '')).strip()
        top = int(arguments.get('top', 5) or 5)
        documents = search_documents(query, settings, top=max(1, min(top, 8)))
        return {
            'query': query,
            'documents': [
                {
                    'id': document.get('id'),
                    'title': document.get('title'),
                    'heading': document.get('heading'),
                    'file_path': document.get('file_path'),
                    'content': document.get('content'),
                }
                for document in documents
            ],
        }, documents

    if tool_name == 'list_foundry_deployments':
        return {'deployments': sorted(list_deployment_names(settings))}, []

    raise RuntimeError(f'Unsupported tool call: {tool_name}')


def summarize_evidence(topic: str, settings: AppConfig | None = None) -> str:
    """Use the summary deployment for short evidence summaries.

    PowerShell bridge:
        - This function exists to show task-based model selection, even if a lab uses the
            same model for both tasks.
        - It mirrors the idea of having a separate script path for a summary-oriented task
            versus a full question-answering task.
    """

    active_settings = settings or AppConfig.from_env()
    # The summary path skips retrieval because it is meant for compact topic summaries
    # rather than grounded question answering.
    with open_project_client(active_settings) as project_client, project_client.get_openai_client() as openai_client:
        response = openai_client.responses.create(
            model=active_settings.azure_ai_summary_deployment,
            instructions='Summarize the topic in two short paragraphs for an identity security engineer.',
            input=topic,
        )
        return response.output_text or 'No summary text was returned by the model.'


def format_grounding_context(search_results: list[dict[str, Any]]) -> str:
    """Turn retrieved documents into a prompt-ready evidence block.

    PowerShell bridge:
    - This is like formatting a list of objects into a readable string block before
      passing it to another command.
    """

    if not search_results:
        return 'No grounded documents were retrieved from Azure AI Search.'

    sections: list[str] = []
    for item in search_results:
        # Keep each record readable by separating fields on new lines.
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
    """Append a deterministic source list to the model response.

    PowerShell bridge:
    - This is similar to adding a final report section after the main output has been
        created.
    - We do this in code so the citation list does not depend entirely on the model
        remembering to format it correctly.
    """

    citations = format_citations(search_results)
    if not citations:
        return answer

    separator = '\n\n' if answer.strip() else ''
    return f'{answer.rstrip()}{separator}Sources:\n{citations}'


def format_citations(search_results: list[dict[str, Any]]) -> str:
    """Format unique source records into a bullet-style reference list.

    PowerShell bridge:
    - This is like using a hash set to remove duplicates before writing a report.
    """

    lines: list[str] = []
    seen_ids: set[str] = set()

    for item in search_results:
        document_id = str(item.get('id') or '').strip()
        if not document_id or document_id in seen_ids:
            continue

        # Duplicate IDs are skipped so the same source does not appear multiple times.
        seen_ids.add(document_id)
        lines.append(
            f"- {document_id} | {item.get('title')} | {item.get('file_path')}")

    return '\n'.join(lines)
