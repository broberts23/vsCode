# Sample ITSM request payloads

Use these JSON files with Swagger (`POST /v1/requests`) or curl.

## Live tenant notes

- Replace the placeholder owner GUID (`00000000-0000-0000-0000-000000000001`) with a real Entra user or service principal object ID from your tenant. Invalid owner IDs are skipped with a warning in Live mode and do not fail the vend job.
- Replace `callbackUrl` with your own HTTPS callback (for example a temporary [webhook.site](https://webhook.site) URL), or omit the field and poll instead.
- For DryRun local testing, the example owner IDs are fine because Graph is never called.
- For the AKS SKU, set `aksServiceAccount` to your Kubernetes service account subject and `allowedIpRanges` to the egress CIDR you want the Conditional Access template to encode.
- For `privileged-payroll-api`, no extra parameters are required. The catalog stamps CAE (`xms_cc` / `cp1`) on the app and encodes a one-hour sign-in frequency on the Conditional Access policy. Graph currently rejects CAE `strictEnforcement` session controls (error 1138), so that mode is not stamped. Clients that call the API must still declare the `cp1` client capability when requesting tokens.
