# Azure DevOps Wiki REST API Reference

Quick reference for the Azure DevOps Wiki Pages REST API (v7.1).

## Authentication

The copilot uses PAT (Personal Access Token) authentication with the `Wiki Read & Write` scope.

Header: `Authorization: Basic {base64(":" + pat)}`

PAT generation: `https://dev.azure.com/{organization}/_usersSettings/tokens`

## Endpoints Used

### Get Page

```
GET https://dev.azure.com/{org}/{project}/_apis/wiki/wikis/{wikiId}/pages?path={path}&api-version=7.1&includeContent=true
```

Returns 200 with page content, or 404 if page doesn't exist.
Response includes `ETag` header for version tracking.

### Create or Update Page

```
PUT https://dev.azure.com/{org}/{project}/_apis/wiki/wikis/{wikiId}/pages?path={path}&api-version=7.1
Content-Type: application/json
If-Match: {version}  (optional — only when updating existing page)

{"content": "markdown content here"}
```

Returns 201 (created) or 200 (updated).

### Delete Page

```
DELETE https://dev.azure.com/{org}/{project}/_apis/wiki/wikis/{wikiId}/pages?path={path}&api-version=7.1
```

### List Pages

```
GET https://dev.azure.com/{org}/{project}/_apis/wiki/wikis/{wikiId}/pages?api-version=7.1&recursionLevel=full
```

## Rate Limits

Azure DevOps REST API enforces rate limits. The copilot respects these by:

- Making sequential (not parallel) PUT requests per page
- Using ETag-based conditional updates to avoid unnecessary writes
- Handling 429 (Too Many Requests) with exponential backoff
