# Python For PowerShell

This project uses only a small set of Python patterns. Here is the shortest practical translation guide.

| Python pattern | What it means here | Rough PowerShell equivalent |
| --- | --- | --- |
| `from package.module import name` | Import one thing from another file/package | `using module ...` or dot-sourcing plus calling a known function/class |
| `def name(arg: str) -> str:` | Define a function, with type hints for input/output | `function Name { param([string]$Arg) [string] ... }` |
| `-> str` / `-> None` | Return type hint only; not a pipe operator | Declared output intent or `[void]` style expectation |
| `str \| None` | Value can be a string or null | `[string]` that may be `$null` |
| `list[dict[str, Any]]` | A list of dictionaries | `System.Collections.Generic.List[hashtable]` conceptually |
| `ClassName(...)` | Construct an object instance | ` [ClassName]::new(...) ` |
| `@dataclass` | Auto-generates boilerplate for a data-focused class | A light class/record pattern without hand-writing constructors |
| `if __name__ == "__main__":` | Run this block only when the file is executed directly | Script entry-point behavior versus imported helper code |
| `__file__` | Current file path | `$PSCommandPath` |
| `f"Value: {name}"` | String interpolation | `"Value: $name"` or `"Value: $($name)"` |
| `[item for item in items if test]` | Build a filtered/transformed list in one expression | `foreach` / `Where-Object` / `ForEach-Object` pipeline pattern |
| `dict.get("key")` | Read a dictionary key without throwing if missing | `$hash['key']` with null-safe intent |
| Leading `_name()` | Internal helper by convention | Private helper naming convention |

Two special notes for this repo:

- `from __future__ import annotations` tells Python to treat type hints more lazily, which makes cross-file typing simpler.
- The Azure SDK clients in Python are normal objects. Think `client = SearchClient(...)` and then `client.search(...)` as the same pattern as creating an SDK object in PowerShell and calling methods on it.

## chat.py Mental Model

If you read [src/rag/chat.py](src/rag/chat.py) like a PowerShell script, the flow is:

1. Import SDK types and helper functions, similar to loading modules and helper functions first.
2. Calculate the project root from `__file__`, similar to using `$PSCommandPath` to locate sibling files.
3. `answer_question()` is the orchestrator function: retrieve records, call the model, append sources, then mask output.
4. `search_documents()` is the Azure AI Search call: create a client, run a query, and reshape each result into a normal dictionary.
5. `complete_with_openai()` is the Azure OpenAI call: read env vars, build a credential chain, create the client, and send messages.
6. `_format_grounding_context()` converts the search results into the plain-text evidence block passed to the model.
7. `append_citations()` and `_format_citations()` make source attribution deterministic even if the model forgets to cite.
8. `_get_required_env()` and `_get_env()` are just small guard/helper functions, like private helper functions at the bottom of a PowerShell script.
