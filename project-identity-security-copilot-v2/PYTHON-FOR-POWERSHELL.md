# Python For PowerShell — v2 patterns

This is a placeholder for the v2 translation guide. The v1 `PYTHON-FOR-POWERSHELL.md` covers the small set of patterns that appear in the carried-over modules. The v2 guide will add three new sections:

- **MCP stdio servers.** A Python module that exposes tool functions and a `mcp.run()` entry point. Roughly equivalent to a small PowerShell module that registers cmdlets and then `Register-Server` is called.
- **A2A handoffs.** A typed `@dataclass` envelope that serialises to JSON, similar to a PowerShell `pscustomobject` that you `ConvertTo-Json -Depth N` and hand to another runspace.
- **Async runner.** `async` / `await` for the coordinator and the delegated runner, so multiple specialist calls can be issued concurrently. PowerShell already does this naturally with `ForEach-Object -Parallel` and `Start-ThreadJob`, but the Python pattern is worth being explicit about.

The rest of the v1 patterns (`@dataclass`, `argparse`, `pathlib`, `f"..."`, `dict.get`, `if __name__ == "__main__":`) all carry over unchanged.
