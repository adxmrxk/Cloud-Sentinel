# CloudSentinel

CloudSentinel scans an AWS account on a schedule for publicly exposed S3 buckets. It rates each finding by severity, stores every audit, and alerts when something is exposed.

## How it works

```
EventBridge (24h) ──▶ Step Functions
                        1. Auditor (.NET 8)    scans every bucket
                        2. Reporter (Flask)    stores the audit (clean ones too)
                        3. Findings?  yes ──▶ SNS alert
                                      no  ──▶ done
```

On Kubernetes, a CronJob runs the same auditor, which POSTs its results straight to the reporter.

**Auditor.** It scans buckets in parallel (16 at a time by default). For each one it reads the Public Access Block, the bucket policy and the ACL, then works out the bucket's effective exposure.

| Severity | Trigger |
|----------|---------|
| `CRITICAL` | Actually public: a public policy or ACL that the Public Access Block doesn't neutralise. Also any bucket with no Public Access Block |
| `HIGH` / `MEDIUM` / `LOW` | 3 / 2 / 1 of the 4 Public Access Block settings disabled |

**Reporter.** A Flask app that runs both as a Lambda (through Mangum) and as a container.

- `POST /ingest` requires a bearer token (`INGEST_API_KEY`) and validates the payload schema.
- `POST /ingest` honours an `Idempotency-Key`, so retried deliveries are stored once.
- Audits go to DynamoDB, and each finding is also written to PostgreSQL.
- Slack alerts are sent in the background, with retries.
- The dashboard (`GET /`) pages through an index rather than scanning the table, and is cached in Redis.

## Performance

These are before and after measurements from the benchmarks run on the current code.

| Metric | Before | After |
|--------|--------|-------|
| Scan of 1,000 buckets (40 ms per S3 call) | 48.4 s | 6.2 s |
| Publicly exposed buckets rated CRITICAL | 1 / 5 | 5 / 5 |
| Scans delivered with a 30% flaky reporter | 70% | 98.5% |
| `/ingest` p95 with a slow Slack webhook | 2,012 ms | 8 ms |
| Dashboard at 5,000 audits | 792 ms, 6 MB | 8 ms, 32 KB |
| Findings API p50 (connection pool) | 8.2 ms | 0.8 ms |
| Malformed payloads causing HTTP 500 | 11 / 22 | 0 / 22 |

## Quick start (local)

```bash
cp .env.example .env
docker compose up -d                                  # full stack with local DynamoDB and S3 mocks
docker compose --profile scan run --rm auditor-scan   # scan the seeded demo buckets
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:8000 |
| Grafana | http://localhost:3000 |
| Prometheus | http://localhost:9090 |
| Jaeger | http://localhost:16686 |

If a port is already taken, override it, e.g. `GRAFANA_PORT=3300`.

## Deploy

```bash
sam build && sam deploy --guided                  # AWS: Lambdas, Step Functions, DynamoDB, SNS
kubectl apply -k k8s/overlays/local               # Kubernetes with local AWS mocks
helm install cloudsentinel helm/cloudsentinel     # Helm, with Redis, Postgres and Grafana
```

`terraform/` provisions the supporting AWS resources: KMS keys, logging and the state machine.

## Configuration

| Variable | Purpose |
|----------|---------|
| `INGEST_API_KEY` | Bearer token for `/ingest`, shared by the auditor and the reporter |
| `TABLE_NAME` | DynamoDB table (default `SecurityAudits`) |
| `DATABASE_URL` | PostgreSQL findings store (optional) |
| `REDIS_URL` | Dashboard cache (optional) |
| `SLACK_WEBHOOK_URL` | Slack alerts (optional) |
| `AUDITOR_MAX_CONCURRENCY` | Buckets scanned in parallel (default 16) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Enables tracing (optional) |

## Tests

```bash
dotnet test tests/Auditor.Tests/Auditor.Tests.csproj   # 32 tests
pip install -r reporter/requirements-dev.txt && pytest reporter/   # 102 tests, 92% coverage
```

CI runs both test suites, Checkov and tfsec, a Helm chart check and a Kubernetes end-to-end test on kind.

## License

MIT. See [LICENSE](LICENSE).
