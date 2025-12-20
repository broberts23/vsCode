# infra

This folder is intended for Bicep templates to deploy the Azure-side components for the ServiceNow governance integration.

Planned resources:
- Function App (Timer trigger + optional HTTP trigger)
- Storage account (Functions runtime)
- Application Insights
- Key Vault (Graph client secret or certificate)
- Optional: App Service Authentication (Entra ID OAuth) for HTTP endpoints

Non-goals (initial):
- No UI resources
- No complex networking (private endpoints) unless required later
