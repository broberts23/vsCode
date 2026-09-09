# Sample ITSM request payloads

Use these JSON files with Swagger (`POST /v1/requests`) or curl.

## Live tenant notes

- Replace `REPLACE_WITH_USER_OR_SP_OBJECT_ID` with a real Entra user or service principal object ID from your tenant. Invalid owner IDs are skipped with a warning in Live mode and do not fail the vend job.
- Replace `REPLACE_WITH_YOUR_ID` in `callbackUrl` with a temporary [webhook.site](https://webhook.site) URL (or leave the field out if you prefer polling).
- For DryRun local testing, placeholder owner IDs are fine because Graph is never called.
- For the AKS SKU, set `aksServiceAccount` to your Kubernetes service account subject and `allowedIpRanges` to the egress CIDR you want the Conditional Access template to encode.
