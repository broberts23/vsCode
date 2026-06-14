"""Azure DevOps authentication helpers.

Manages PAT-based authentication for Azure DevOps REST API calls.
The PAT is read from the AZURE_DEVOPS_PAT environment variable and encoded
as a Basic auth header. No secrets are stored in code.
"""

from __future__ import annotations

import base64
import os


def get_auth_header() -> dict[str, str]:
    """Build the Authorization header for Azure DevOps REST API calls.

    Returns a dict with the 'Authorization' key set to a Basic-encoded PAT.
    """
    pat = os.environ.get('AZURE_DEVOPS_PAT', '')
    if not pat:
        raise RuntimeError(
            'AZURE_DEVOPS_PAT is required for Azure DevOps REST API calls. '
            'Generate a PAT at https://dev.azure.com/{org}/_usersSettings/tokens '
            'with the Wiki Read & Write scope.'
        )
    encoded = base64.b64encode(f':{pat}'.encode('utf-8')).decode('utf-8')
    return {'Authorization': f'Basic {encoded}'}
