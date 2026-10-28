# Learning with coding agents

The API was never the hard part. A FastAPI process, three verbs, a Cosmos document with an id and a display name: that is an afternoon if you let the agent run. The hard part was staying able to explain the token. Who the app registration is for, why Swagger and a daemon are not the same caller, why a green Authorize button can still 401, and why Azure will happily mint a v1 access token after you asked the v2 endpoint for one. [VibeWise](https://github.com/broberts23/vibe-wise) is a Cursor skill I built for that gap. Learn mode is the piece that refuses to finish the design while you watch. This project, a small identity API on Container Apps, was the backdrop I used it against.

## What Learn mode is

VibeWise Learn is a learning-first mode for Cursor Agent, tuned for Azure, Entra ID, Bicep, and Python that talks to Microsoft with the official SDKs. The short version on the repo is accurate: you build, the agent writes. You own the design. The agent asks how you would approach the next slice, answers the reasoning you actually gave, and explains a concept when the concept is the thing in the way. It does not invent your subscription model, your identity layout, or your privilege model and then ask you to nod.

The loop has three checkpoints, and they are not a ceremony you march through every time. A Build checkpoint is an open question: how would you do this? A Design checkpoint restates the approach you just stated, including the tradeoff, and waits. Confirm and continue records it and keeps planning. It does not authorize code. An Implementation checkpoint is the first moment the agent is allowed to name the files it is about to touch. Implement this step is the yes. Discuss is the other door, on purpose, so a number is not the only way to respond when something still feels wrong.

When the topic is a Microsoft product fact, the skill is supposed to look it up. Microsoft Learn's MCP tools (`microsoft_docs_search`, then fetch or a code sample when the search chunk is too thin) sit in front of teaching. That mattered here more than once. App roles, delegated scopes, SPA redirect rules, and which claim decides v1 versus v2 access tokens are all things a model will half-remember. Learn mode is not allowed to half-remember them out loud.

Experience changes how much grounding you get, not who decides. I came in as a beginner at Python and at FastAPI, intermediate on Container Apps and Cosmos, and already deep on Entra, Bicep, and PowerShell. The skill kept the identity decisions in my mouth anyway. Being fluent in Entra did not license the agent to pick the scope, the redirect URI, or the token version.

## How you turn it on

You need Cursor. The skill itself is installed like any other Agent Skill:

```sh
npx skills add broberts23/vibe-wise
```

That drops Learn and Reset into the user or project skills folders, depending on where you install them. A skills-only install does not wake itself up on the next chat. You start it, and you resume it, the same way:

```text
/vibe-wise-learn
```

The first run in a repo with no notes is onboarding, one question at a time, numbered, and it waits. New project, existing repo, or a codebase you already know. Then programming experience, then the stack, then whether you want the defaults. Defaults mean normal checkpoints, open questions, and the agent writes the code after you confirm a step. I took defaults. The skill said it would walk the project end to end as we built it, which is the right default when you are new to the language even if you are not new to the cloud.

State is three Markdown files under `.vibe-wise/` at the git root: `profile.md`, `progress.md`, and `project-map.md`. There is no service behind them. Profile is the compact snapshot of how you want to work. Progress is the learning record, including whatever decision is still pending, so a new chat cannot pretend the last checkpoint was settled. The project map is requirements, components, and unknowns, and it is supposed to stay honest about what is chosen versus what is only proposed. I would gitignore that directory. The skill will not edit `.gitignore` unless you ask.

If you want the notes restored when a chat starts, and Learn MCP wired for you, install the repo as a Cursor plugin. The plugin packages the same skills, a `sessionStart` hook, and an `mcp.json`. On a skills-only install you add Learn yourself:

```json
{
  "mcpServers": {
    "microsoft-learn": {
      "url": "https://learn.microsoft.com/api/mcp"
    }
  }
}
```

No auth. After that, `/vibe-wise-learn` again resumes. It does not reset. Reset is a separate command, and it asks before it archives the notes.

## The backdrop

The thing I wanted was ordinary on a slide and fiddly in a tenant. A Python FastAPI app with GET, PUT, and PATCH, hosted later on Azure Container Apps, persisted in Cosmos DB. Entra app-role claims would separate a human using Swagger from a machine calling the API directly. The browser would sign in to reach `/docs`. Between Azure services there would be RBAC and no keys. Local testing came first: the Cosmos emulator and its well-known master key, which is a deliberate exception that must not leak into the Azure path. Deploy would be Bicep plus PowerShell: stand up infra, build and push an image, deploy the app again with that image.

That list is a requirement. Learn mode treated it as a requirement. The folder layout, the document shape, the number of app registrations, the scope, the redirect URI, and the order of Azure resources all stayed open until I said them.

## Requirements are not a design

After onboarding, the first Build checkpoint was blunt: what would you build and prove locally first? I answered in the order I actually wanted:

```text
build FastAPI application first, create entra app reg, expose api, create claims.
then dockerfile/compose, docker build and debug locally using azure cosmos emulator
using well-known master key
```

The agent did not start scaffolding. It wrote the sequence back, flagged the tension, and stopped. Entra roles and a Swagger sign-in only pay off once the API validates JWTs. "Build the app first" can mean routes with no auth, or routes that already demand a token. Those are different first slices. I confirmed the sequence, with auth deferred until the app registration existed, and a Compose file that was only the API and the emulator.

The next checkpoint asked what the routes were about, and how I would lay the Python out. I was explicit that the document contract was not the point:

```text
/api and main.py for the api, /src for the modules. /infra for the bicep and /script
for the powershell. the document contract isn't the focus, basic idenity mockup is fine.
```

That became `api/main.py`, modules under `src/`, empty `infra/` and `script/`, and a mock identity of `id` plus optional `displayName`, partition key `/id`. The project folder name was mine too: `project-fastapi-swagger-auth-roles`. Only then did an Implementation checkpoint list the files. Confirming it is what created the skeleton. Until that yes, the repo did not grow a speculative auth middleware "to save time."

## One app, two roles

Identity was the part I already knew how I wanted to feel, and the skill still made me say it:

```text
one app. two roles. role.admin for human swagger access, role.service for machin
direct api access.
```

The reply was a concept, not a portal script. App roles carry `allowedMemberTypes`. A User role is what you assign to a person. An Application role is what you assign to another app or a managed identity on the client-credentials flow. Mapping `role.admin` to User and `role.service` to Application is how you stop a daemon from accidentally holding the human Swagger role. The Design checkpoint recorded that, plus a proposal I could have rejected: identity routes would later accept either role, and the Swagger browser flow would be the one that expects `role.admin`. I confirmed it. The app registration still did not exist, because creating it was the next decision, not a side effect of the last one.

## The blank it would not fill

This was the turn I was least sure about, and I said so:

```text
this the part i'm the most unsure about.
i'll create the app in the entra portal. the app name will be "project-fastapi-swagger"
the Application ID URI will the api://{appId}. i don't know what the scopes and
Authorized client applications will be
```

Learn mode went to Microsoft Learn before it taught. Scopes and app roles are different surfaces. A scope is a delegated permission. It shows up in `scp` when a signed-in user asks for an access token. An app role shows up in `roles`. My machine caller did not need a delegated scope. Swagger's browser flow did, because that is how a user token for your own API gets issued at all. Authorized client applications is not a free "skip consent" switch. You preauthorize a client for a specific scope. With no scopes, the portal has nothing to attach the client id to.

I still tried to defer the scope and preauthorize the same app:

```text
Expose the API under "Expose an API" but leave scoped blank (defer) and populate
the Authorized client applications with the same app’s client ID
```

The next message did not implement a compromise. It said the two halves cannot both be true, and handed the Build checkpoint back. I chose the thin scope Learn's own samples use when roles do the real authorization:

```text
add one minimal scope now (access_as_user)
```

That is the interaction I built the skill for. The agent can name the conflict and the docs. It cannot pick `access_as_user` for you and call it your design. After I said it, the Design checkpoint was allowed to exist: one app, `api://{appId}`, scope `access_as_user`, the app's own client id authorized for that scope, `role.admin` for users, `role.service` for applications. I created that registration in the portal. The skill did not click the portal for me.

## The redirect URI I got wrong, and the token version the portal hid

Swagger in the browser is a public client. The skill laid out the options and recommended authorization code with PKCE on a Single-page application redirect, with the client secret left out of the picture. I picked that and gave a host:

```text
A. http://127.0.0.1:8000
```

Entra will not take it. For an SPA redirect, `http://localhost` is allowed and `http://127.0.0.1` is not. I had to correct the checkpoint myself:

```text
1 but change `http://127.0.0.1:8000/docs/oauth2-redirect` to
`http://localhost:8000/docs/oauth2-redirect`. only "https://url" or
"http://localhost" is supported
```

The Implementation checkpoint that followed was the first time FastAPI grew JWT checks and a Swagger OAuth scheme. Until then, `/docs` was anonymous on purpose.

Then the UI lied in a familiar way. Authorize opened a modal with a client id and a client secret. That modal is Swagger UI drawing every authorization-code field it knows. For this app the secret stays empty. PKCE is the proof. "Authorized" only means Swagger holds a token. It does not mean the API accepted it. The first calls came back as invalid or expired, and the server was checking issuer against the v2 form, `https://login.microsoftonline.com/{tenant}/v2.0`. A fresh InPrivate window did not fix it. The detail, once we surfaced it, was the whole story:

```text
token iss='https://sts.windows.net/7c029110-ec6b-48a2-a1ec-5bdec806f9ce/',
aud='api://8f99f135-63dd-4679-88b7-32ad6ebf4219', ver='1.0';
expected issuer='https://login.microsoftonline.com/7c029110-ec6b-48a2-a1ec-5bdec806f9ce/v2.0'
```

Calling the v2 authorize endpoint does not force a v2 access token. The resource app owns the access-token version. In the Graph-shaped manifest that property is `api.requestedAccessTokenVersion`. Mine was null, which means v1, which means `sts.windows.net` and `ver` 1.0. I set it to 2, signed out of Swagger, signed in again, and GET and PUT returned 200. A later GET 500 was unrelated and smaller: Cosmos returns `_rid`, `_etag`, `_ts` and the Pydantic model had been told to forbid extra fields. PUT had been returning the object we sent, so it never noticed.

I asked for the verbose 401 text to come back out once v2 was real. The skill treated that as an implementation I had named, not as a chance to reopen the identity design.

## Deploy stayed a conversation

The Dockerfile and `pyproject.toml` were already on disk when we turned to Azure. I still had to say the shape:

```text
azure resources should be ACR, ACA environment, Cosmos, then SMI role assignments
bicep should accept an input variable for the ACR name and container image,
and pull hello world if blank for first deployment.
subsquent deployment will pull real container image
1 powershell script to deploy bicep
1 powershell script to docker build and push to ACR
1st powershell script again to deploy container
```

The Design checkpoint added the pieces I had not spelled: a Container App, not only an environment, because a system-assigned identity has to belong to an app; Cosmos SQL with database `identitydb` and container `identities`; the built-in Cosmos data contributor role on that identity; AcrPull so the app can pull from a registry with admin user disabled; hello-world from `mcr.microsoft.com/azuredocs/containerapps-helloworld:latest` when the image parameter is empty, on port 80, and the real image on 8080. The scripts landed in `script/Deploy-Infrastructure.ps1` and `script/Build-Push-Image.ps1`. The first pass bootstraps. The second pass is the same Bicep with `-ContainerImage`.

Azure did not reward the plan with a clean apply. Cosmos account creation in Australia East died with a control-plane 408, and the account sat on "Not available" long after the deployment was marked failed. Learn mode did not rewrite the template into a different product. It said the script was not the bug, the account was stuck, and the next deploy would keep colliding with it until it was deleted or the platform finished. Separately, the Container App name `ca-fastapi-swagger-api-dev-5zlni` was rejected. I went looking for a double hyphen. There isn't one in the Bicep. The name is single hyphens stacked on a `baseName` that already contains a hyphen, and it is 33 characters. Container Apps allow 32, and the error text mentions `--` in the same sentence as the length rule. The skill's job there was to point at the line, not to silently `take()` the string and call the deploy done.

[Screenshot: resource group after a successful deploy, with the container registry, Container Apps environment, Container App, and Cosmos account all present.]

[Screenshot: Container App revision running the real image, ingress hostname visible, system-assigned identity enabled.]

[Screenshot: Cosmos DB SQL role assignment granting the Container App's managed identity data-plane access, with local authentication disabled on the account.]

[Screenshot: Swagger at the Container App URL after an Entra sign-in, Authorize showing the lock, and a GET that returns 200.]

The SPA redirect for that hostname is a portal edit the template cannot finish for you: `https://<apiFqdn>/docs/oauth2-redirect`, platform Single-page application. Localhost remains the local one. They are not interchangeable, which is the same lesson as `127.0.0.1`.

## What the session leaves behind

When the chat is gone, `.vibe-wise/` is the part that still knows the decisions. Profile says the stack levels and that learning mode is on. Progress says `requestedAccessTokenVersion` was null and that setting it to 2 is what made the v2 issuer check pass. The project map says one app, `access_as_user`, `role.admin` and `role.service`, emulator key only on the local path. None of that is a substitute for the portal. It is how the next `/vibe-wise-learn` avoids re-onboarding me and avoids "helpfully" reintroducing a client secret, a second app registration, or a v1 issuer exception I already told it to remove.

That is the use of the skill, and that is the interaction. It is slower than letting an agent invent a working demo. It is faster than discovering, in a private browser, that you cannot explain why the token says 1.0.
