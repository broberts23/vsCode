# Python For PowerShell

This project uses only a small set of Python patterns. This file is the shortest practical translation guide.

| Python pattern | What it means here | Rough PowerShell equivalent |
| --- | --- | --- |
| `from package.module import name` | Import one symbol from another file | `using module` or dot-sourcing a file and calling a known function |
| `def name(arg: str) -> str:` | Define a function with type hints | `function Name { param([string]$Arg) [string] ... }` |
| `class Name:` | Define a class | `class Name { ... }` |
| `@dataclass` | Auto-generate common data-class boilerplate | A lightweight record-like class |
| `-> None` | Function returns nothing intentionally | `[void]` style intent |
| `str \| None` | Value can be a string or null | `[string]` that may be `$null` |
| `list[dict[str, str]]` | A list containing dictionaries | List of hashtables conceptually |
| `if __name__ == "__main__":` | Run code only when the file is executed directly | Script entry point behavior |
| `Path(__file__)` | Current script file path | `$PSCommandPath` |
| `f"Value: {name}"` | String interpolation | `"Value: $name"` |
| `dict.get("key")` | Read a dictionary key without failing when absent | Hashtable lookup with null-safe intent |
| leading `_helper()` | Internal helper by convention | Private helper naming style |

## Mental model for this repo

Read the Python files the same way you would read a small PowerShell module.

1. `src/app.py` is the entry script.
2. `src/config.py` is the configuration helper.
3. `src/foundry/project_client.py` is the client-construction helper.
4. `src/search/*.py` are the retrieval and indexing helpers.
5. `src/rag/chat.py` is the orchestration function.

## Important translation notes

- Python type hints describe intent. They do not enforce types at runtime by themselves.
- `DefaultAzureCredential()` is an object that knows how to try multiple login sources. Think of it as a smart credential provider, not the token itself.
- SDK clients are normal Python objects. The pattern is usually `client = SomethingClient(...)` followed by `client.method(...)`.
- A dataclass is mainly a concise way to define structured data without hand-writing constructors and display methods.

## Reading strategy

If you already know PowerShell well, do not try to learn all of Python first. Learn only the patterns that appear in this repo, then follow the data flow:

1. load config
2. create clients
3. load markdown
4. upload search docs
5. run retrieval
6. call the model
7. return the answer
