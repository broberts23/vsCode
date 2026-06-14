# Mermaid Diagram Templates

Reference templates for Mermaid diagrams compatible with Azure DevOps Wiki.

## Class Diagram

Used when 2+ classes are defined in a module.

```
::: mermaid
classDiagram
    class ServiceClass {
        +handle_request(data: dict) Response
        +validate_input(data: dict) bool
    }
    class BaseService {
        +log(message: str) None
    }
    BaseService <|-- ServiceClass
:::
```

## Sequence Diagram

Used when 3+ functions with decorator-based roles are detected.

```
::: mermaid
sequenceDiagram
    title Request Processing Workflow
    participant R as authenticate (Router)
    participant V as validate (Function)
    participant H as handle (Function)
    R->>+V: invoke
    V->>+H: invoke
    H-->>-V: Response
    V-->>-R: Response
:::
```

## Flowchart (using `graph` — Azure DevOps Wiki compatible)

```
::: mermaid
graph TD
    N0[init_config]
    N1[load_data]
    N2[process_records]
    N0 --> N1
    N1 --> N2
:::
```

## Important Constraints

- Use `graph` not `flowchart` — Azure DevOps Wiki Mermaid renderer does not support `flowchart`.
- Use `---->` not `-->>` for sequence arrows (LongArrow unsupported).
- No HTML tags inside diagrams.
- No Font Awesome icons.
- Supported diagram types: `sequenceDiagram`, `graph`, `classDiagram`, `stateDiagram-v2`, `gantt`, `pie`, `journey`, `erDiagram`, `gitGraph`.
