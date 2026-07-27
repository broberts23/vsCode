# Bootstrapping Your Lab: Building an Automated Entra ID Seeder & Custom SCIM 2.0 Gateway in Python

Setting up an identity lab usually leaves you staring at a blank tenant. No users, no groups, no organizational structure—just a directory-shaped void waiting to be filled. If you're trying to get hands-on with zero-trust patterns, secretless containerized compute, or user-context security pipelines, you need realistic directory infrastructure to practice against. You can't test SCIM provisioning against zero users. You can't validate group-based access policies against a single admin account.

So I built a project that solves both sides of the problem: a deterministic seed script that populates a blank Entra ID tenant with enterprise-grade test data, and an RFC-compliant SCIM 2.0 gateway deployed to Azure Container Apps that runs entirely without hardcoded secrets. The whole thing is written in Python, deployed with a single Bicep template, and costs roughly nothing when idle.

The code lives at `entra-scim-seeder/`, and walking through the repo tells the story of how the two halves fit together.

## Structure of the Project

```text
entra-scim-seeder/
├── .env.example
├── Dockerfile
├── requirements.txt
├── infra/
│   └── main.bicep
├── seeder/
│   ├── auth.py
│   ├── generator.py
│   └── seed_tenant.py
└── scim_gateway/
    ├── config.py
    ├── database.py
    ├── main.py
    ├── models.py
    ├── schemas.py
    └── routes/
        └── users.py
```

The `seeder/` directory runs on your local machine. It uses the Microsoft Graph Python SDK to create users and groups with a single invocation. The `scim_gateway/` directory is a FastAPI application that gets containerized and deployed to Azure Container Apps. It implements the System for Cross-domain Identity Management (SCIM) 2.0 specification—the protocol that Entra ID uses to synchronize users and groups to downstream applications.

The `infra/` directory contains a single Bicep template that deploys every Azure resource the SCIM gateway needs: a user-assigned managed identity, Key Vault, Azure Container Registry, Cosmos DB, a Log Analytics workspace, and the Container App itself. All RBAC role assignments are baked in. All outputs are formatted to populate a `.env` file directly.

## Phase One: Respawning the Directory

The seeder is straightforward by design. You register an Entra ID application with `User.ReadWrite.All` and `Group.ReadWrite.All` application permissions, drop the tenant ID, client ID, and client secret into `.env`, and run:

```shell
python -m seeder.seed_tenant --users 100
```

The `auth.py` module initializes a `GraphServiceClient` using `ClientSecretCredential` from `azure-identity`:

```python
def get_graph_client() -> GraphServiceClient:
    tenant_id = os.environ["TENANT_ID"]
    client_id = os.environ["CLIENT_ID"]
    client_secret = os.environ["CLIENT_SECRET"]

    credential = ClientSecretCredential(
        tenant_id=tenant_id, client_id=client_id, client_secret=client_secret,
    )
    return GraphServiceClient(credential, scopes=["https://graph.microsoft.com/.default"])
```

The `generator.py` module uses Faker to produce realistic profiles. It seeds the random generator with a fixed value so every run produces the same users—useful for reproducing test scenarios. Users are assigned to one of eight departments (Engineering, Data Science, Security, DevOps, Product, Finance, Human Resources, Marketing) and one of ten job titles. The domain suffix comes from the environment variable, so you can target any tenant's UPN format.

The real work happens in `seed_tenant.py`. It runs three sequential phases: create users, create groups, then bind memberships. The group set is static—three security groups called `App-AI-Standard`, `App-AI-Privileged`, and `Omit-AI-Access`. The membership assignment logic maps department and job title to group membership:

* Data Science and Engineering users land in `App-AI-Standard`.
* Lead AI Engineers and Cloud Architects land in `App-AI-Privileged`.
* Everyone else lands in `Omit-AI-Access`.

The binding step posts to `$ref` endpoints, which is where the first real-world gotcha appears. Graph's directory store is distributed across multiple replicas. A group creation call returns HTTP 201 with the new object ID, but a membership write that references that same group a second later might hit a replica that hasn't converged yet. The result is a 404 that looks like a bug but is actually eventual consistency. The code handles this with exponential backoff on all three write operations—user creation, group creation, and `$ref` binding—with a ten-second settling pause between group creation and membership assignment. The retry parameters live at the top of the file as constants you can tune:

```python
MAX_RETRIES = 5
INITIAL_BACKOFF_SECONDS = 2.0
MAX_BACKOFF_SECONDS = 30.0
POST_CREATE_SETTLING_SECONDS = 10
```

## Phase Two: The SCIM Gateway

The SCIM gateway is where the architecture gets interesting. It's a FastAPI application that exposes four endpoints under the `/scim/v2` prefix: `GET /Users`, `POST /Users`, `PATCH /Users/{id}`, and `DELETE /Users/{id}`. Every request is authenticated with a bearer token that the gateway reads from Azure Key Vault at runtime—no static secrets in configuration files or environment variables.

The backend store is Cosmos DB, chosen because it gives us a serverless, globally-distributed document store with a free tier that covers the first 1000 RU/s and 5 GB of storage. The user documents are partitioned by `userName`, which matches the natural access pattern of the SCIM protocol (Entra queries by `userName eq "..."` before every operation).

The gateway initializes the Cosmos database and container during the FastAPI lifespan event. It uses `ManagedIdentityCredential` with the user-assigned managed identity's client ID, falling back to `DefaultAzureCredential` for local development. The credential helper in `database.py` is explicit about the selection:

```python
def get_credential():
    client_id = os.environ.get("AZURE_CLIENT_ID")
    if client_id:
        return ManagedIdentityCredential(client_id=client_id)
    return DefaultAzureCredential()
```

The bare `DefaultAzureCredential` approach is a trap I hit early on. In a container that has a user-assigned managed identity attached, `DefaultAzureCredential` iterates through eight credential types before settling on `ManagedIdentityCredential`, and when it does, it doesn't know which user-assigned identity to target. The log shows it trying EnvironmentCredential, WorkloadIdentityCredential, SharedTokenCacheCredential, VSCode, Azure CLI, Azure PowerShell, Azure Developer CLI, and finally the MSI endpoint—which returns a 400 because the `resource` parameter doesn't map to a configured identity. The fix is to set `AZURE_CLIENT_ID` as an environment variable on the container and use `ManagedIdentityCredential` directly.

The SCIM schema definition in `schemas.py` is another place where the real protocol deviates from the textbook. The `name` attribute in SCIM is optional per RFC 7643, but many implementations model it as required. Entra ID's provisioning service sends the `name` object only when it has structured name data—otherwise it sends `displayName` alone. The `_derive_names` helper in `routes/users.py` walks through a fallback chain: structured name fields first, then the formatted name (split on the first space), then `displayName`, then `userName` as a last resort.

```python
def _derive_names(body: ScimUserCreate) -> tuple[str, str, str]:
    given_name = ""
    family_name = ""
    display_name = body.displayName or ""

    if body.name:
        given_name = body.name.givenName or ""
        family_name = body.name.familyName or ""
        if not given_name and not family_name and body.name.formatted:
            parts = body.name.formatted.split(None, 1)
            given_name = parts[0] if parts else ""
            family_name = parts[1] if len(parts) > 1 else ""

    if not given_name and not family_name and display_name:
        parts = display_name.split(None, 1)
        given_name = parts[0] if parts else ""
        family_name = parts[1] if len(parts) > 1 else ""

    if not display_name:
        display_name = f"{given_name} {family_name}".strip() or body.userName

    return given_name, family_name, display_name
```

The PATCH handler is equally pragmatic. Entra sends patch operations like `replace active` with a bool value, or `replace name.givenName` with a string. The operation parser matches on `op` and `path` and applies the mutation in-memory before calling `upsert_item` on the Cosmos container.

## Infrastructure as Code

The Bicep template in `infra/main.bicep` deploys everything. It targets the resource group scope and takes a `baseName` parameter that's used as a suffix for all resource names. The template creates:

* A user-assigned managed identity (free).
* A Key Vault with RBAC authorization enabled (no access policies).
* A Container Registry at the Basic SKU.
* A Cosmos DB account with the free tier flag set.
* A Log Analytics workspace at the PerGB2018 SKU.
* A Container Apps Environment in Consumption mode.
* A Container App with scale-to-zero (minReplicas = 0) and 0.25 vCPU.

The RBAC role assignments are the critical piece. The managed identity needs three roles: `Key Vault Secrets User` on the Key Vault (to read the SCIM bearer token at runtime), `Cosmos DB Built-in Data Contributor` on the Cosmos account (for keyless data-plane access), and `AcrPull` on the registry (to pull the container image at deployment time). The Cosmos DB role assignment is a separate resource type from Azure RBAC—`Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments`—not `Microsoft.Authorization/roleAssignments`. The built-in role definition ID `00000000-0000-0000-0000-000000000002` is auto-provisioned on every Cosmos account, so you only need to create the assignment, not the definition.

The Container App environment variables include `AZURE_CLIENT_ID` set to the managed identity's client ID, which is the signal that `ManagedIdentityCredential` uses to target the correct identity. The SCIM bearer token is generated as a deterministic GUID and stored in Key Vault as a secret, then referenced in the Container App's secret definition with the identity field pointing to the managed identity resource ID.

```bicep
secrets: [
  {
    name: 'scim-bearer-token'
    identity: scimMi.id
    keyVaultUrl: scimBearerSecret.properties.secretUri
  }
]
```

The outputs are designed to be copied directly into a `.env` file. The `scimEndpointUrl` output constructs the full URL that Entra will use for provisioning: `https://<container-app-fqdn>/scim/v2`.

## Connecting Entra ID to the Gateway

Once the infrastructure is deployed and the container image is pushed to ACR, the last step is to configure Entra ID's provisioning. You create a new non-gallery enterprise application, switch the provisioning mode to Automatic, and provide two values: the tenant URL (the `scimEndpointUrl` from the deployment outputs) and the secret token (retrieved from Key Vault with `az keyvault secret show`).

![Entra enterprise app provisioning blade showing a successful test connection](screenshots/entra-test-connection.png)

The test connection validates that the endpoint is reachable, the bearer token is accepted, and the SCIM schema parsing succeeds. If it fails, the most common causes are the missing `https://` prefix, the missing `/scim/v2` path suffix, or the container app not having the `AZURE_CLIENT_ID` environment variable set.

Once the connection passes, you can provision a test user on demand.

![Entra enterprise app provisioning blade showing a successful provision on demand](screenshots/entra-provision-on-demand.png)

The gateway creates the document in Cosmos DB, where you can inspect it through the Data Explorer.

![Azure portal Data Explorer showing the user entry in Cosmos DB](screenshots/cosmos-data-explorer.png)

## Building and Deploying

The container image is built in ACR directly, keeping the pipeline simple:

```shell
az acr build --registry acrscimgty --image scim-gateway:v1 .
```

![Successfully building and pushing the container to Azure Container Registry](screenshots/acr-build-success.png)

The Container App configuration shows the registry, image, and image tag in the portal blade, along with the ingress settings and environment variables.

![Azure Container App blade showing the container name, properties, registry, image, and image tag](screenshots/container-app-blade.png)

## The Wrinkles You'll Hit

Three things surprised me during development, and they're worth calling out because they're not obvious from reading the documentation alone.

Graph eventual consistency is real. The Microsoft Graph documentation mentions it in passing, but you don't appreciate it until you see a `POST /groups` return 201 and an immediate `POST /groups/{id}/members/$ref` return 404 on the same group ID. The retry with exponential backoff handles it, but you need to know it exists before you can design around it.

`DefaultAzureCredential` in a Container App with a user-assigned identity is a footgun. Without `AZURE_CLIENT_ID` set, the credential chain falls through to the Managed Identity endpoint and fails because it doesn't know which identity's token to request. The solution is twofold: set the environment variable in the container definition, and use `ManagedIdentityCredential(client_id=...)` explicitly in code to skip the eight-credential fallback chain entirely.

The `name` field in SCIM is optional in the spec, but required by many schema implementations. Entra ID sends it only when it has the data. A robust SCIM gateway needs to handle the case where the entire `name` object is absent and derive the structured name from `displayName`.

## Closing the Loop

What started as an empty tenant is now a lab you can rebuild on demand: a deterministic Graph seeder that stamps out users, groups, and memberships with enough organizational shape to exercise real access policies, and a SCIM 2.0 gateway that Entra can provision into without a single hardcoded secret in the runtime path. The Bicep template wires the managed identity, Key Vault, Cosmos, and Container App together so the interesting failures—replica lag on `$ref` writes, the wrong identity on the MSI endpoint, a missing `name` object in a PATCH—show up where you can see them, not buried under plumbing. If you're building identity labs, provisioning connectors, or anything that needs directory gravity before the first real user shows up, this pattern is the shortest path from blank directory to something worth testing against.

## References

- [Create a user](https://learn.microsoft.com/en-us/graph/api/user-post-users) 
- [Add a member to a group](https://learn.microsoft.com/en-us/graph/api/group-post-members)
- [Microsoft Graph Python SDK](https://learn.microsoft.com/en-us/graph/sdks/sdks-overview)
- [ClientSecretCredential (azure-identity)](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.clientsecretcredential)
- [SCIM support in Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/scim-support-in-entra-id)
- [How app provisioning works](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/how-provisioning-works)
- [Build a SCIM endpoint for user provisioning](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-build-users-and-groups-endpoints)
- [Tutorial: Develop and plan provisioning for a SCIM endpoint](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups)
- [ManagedIdentityCredential (azure-identity)](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.managedidentitycredential)s
- [Configure role-based access control for Azure Cosmos DB](https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-setup-rbac)
