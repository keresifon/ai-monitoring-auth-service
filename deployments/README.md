# Auth Service Deployment

The auth-service is deployed to the shared `ai-monitoring` namespace in AKS. It provides JWT-based authentication for the AI Log Monitoring system.

## Prerequisites

1. **Shared infrastructure** – Run `install-dependencies.sh` from `ai-monitoring-alert-service/deployments/` first. This creates:
   - `ai-monitoring-secrets` (must include `db-username`, `db-password`, `jwt-secret`, `cors-allowed-origins`, and other shared credentials)
   - PostgreSQL, Elasticsearch, Redis, RabbitMQ

2. **GitHub secrets** (for CI/CD deploy on main):
   - `AZURE_CREDENTIALS` – Azure service principal JSON
   - `AKS_RESOURCE_GROUP` – AKS resource group
   - `AKS_CLUSTER_NAME` – AKS cluster name

## Manual deployment

```bash
# Ensure secret exists (run install-dependencies.sh from alert-service first)
helm upgrade --install auth-service ./charts \
  --namespace ai-monitoring \
  -f charts/values.yaml
```

## Dependencies

- **PostgreSQL** – Uses `postgres` (K8s service) on port 5432. Credentials come from `ai-monitoring-secrets`:
  - `db-username`
  - `db-password`
- **JWT** – `jwt-secret` from `ai-monitoring-secrets`
- **CORS** – `cors-allowed-origins` from `ai-monitoring-secrets`

If `ai-monitoring-secrets` does not include these keys, add them before deploying.
