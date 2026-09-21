# CloudSentinel

**Automated Cloud Security Posture Management (CSPM) Platform**

CloudSentinel is a security governance tool that automatically scans cloud infrastructure for misconfigurations, stores findings in a central datastore, and alerts on vulnerabilities. It is built on a serverless, event-driven architecture and shipped through a full CI/CD pipeline.

---

## Table of Contents

- [Project Overview](#project-overview)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Deployment Options](#deployment-options)
- [Configuration](#configuration)
- [CI/CD Pipeline](#cicd-pipeline)
- [Observability](#observability)
- [Security Hardening](#security-hardening)
- [License](#license)

---

## Project Overview

### What It Is

CloudSentinel is a **Cloud Security Posture Management (CSPM)** platform. It runs on a schedule, scans your cloud environment for misconfigurations that could expose data or violate compliance policies, records findings to a queryable datastore, and notifies your team when something is wrong.

### The Problem It Solves

Misconfigured cloud resources are the **number one cause of real-world data breaches**. The most common culprit is publicly exposed object storage. Capital One, Accenture, and the U.S. Department of Defense have all leaked data through misconfigured S3 buckets.

The challenge is that cloud environments change constantly. New buckets get created, security settings drift, and engineers ship configurations that look fine in isolation but introduce risk at scale. Manual review doesn't scale.

CloudSentinel solves this by:

- Running automated, scheduled scans across the cloud account
- Centralizing findings into a single auditable record
- Scoring each finding by severity so teams can triage
- Alerting on detection so issues are surfaced immediately, not at the next audit

### What It Currently Detects

The current scanner targets the highest-impact misconfiguration class: **AWS S3 bucket public access exposure**. For every bucket in the account, it inspects all four Public Access Block protections and flags any bucket where one or more is disabled.

| Severity | Trigger |
|----------|---------|
| `CRITICAL` | All 4 protections disabled, or no Public Access Block configured at all |
| `HIGH`     | 3 of 4 protections disabled |
| `MEDIUM`   | 2 of 4 protections disabled |
| `LOW`      | 0 to 1 protections disabled |

---

## How It Works

The system runs as a four-stage pipeline orchestrated by AWS Step Functions:

```
        ┌──────────────────────┐
        │  EventBridge (24h)   │   Scheduled trigger
        └──────────┬───────────┘
                   ▼
        ┌──────────────────────┐
        │  Step Functions      │   Orchestration
        └──────────┬───────────┘
                   ▼
   1.  Auditor Lambda  (.NET 8)
       • Lists every S3 bucket in the account
       • Queries PublicAccessBlock config for each
       • Returns JSON: at-risk buckets + severity scores
                   │
                   ▼
   2.  Choice State: any vulnerabilities found?
       │
       ├── NO  ──▶ Workflow ends successfully
       │
       └── YES ──▶
                   │
                   ▼
   3.  Reporter Lambda  (Python / Flask)
       • POST /ingest with audit results
       • Writes findings to DynamoDB
       • Records audit metadata + timestamp
                   │
                   ▼
   4.  SNS Topic: security alert published
       └── Fans out to Slack, email, PagerDuty
                   │
                   ▼
        ┌──────────────────────┐
        │  Dashboard (always)  │   Reporter GET /
        │  Reads DynamoDB and  │
        │  renders audit log   │
        └──────────────────────┘
```

**Key design decisions:**

- **Orchestration is external to the services.** The Auditor and Reporter don't know about each other. Step Functions owns the workflow, which means each component is independently testable and replaceable.
- **The Choice state prevents alert fatigue.** Notifications only fire when vulnerabilities are actually found.
- **The Reporter runs in two modes from one codebase.** Wrapped with Mangum, the same Flask app runs as a Lambda behind API Gateway, and as a containerized service in Kubernetes.

---

## Architecture

```
                    ┌────────────────────────────────────┐
                    │       SCHEDULED TRIGGER LAYER      │
                    │   AWS EventBridge  /  K8s CronJob  │
                    └──────────────────┬─────────────────┘
                                       ▼
                    ┌────────────────────────────────────┐
                    │       ORCHESTRATION LAYER          │
                    │       AWS Step Functions           │
                    └──────────────────┬─────────────────┘
                                       ▼
        ┌──────────────────────────────────────────────────────┐
        │                COMPUTE LAYER                          │
        │  ┌────────────────────┐   ┌────────────────────────┐ │
        │  │  Auditor (.NET 8)  │   │  Reporter (Flask)      │ │
        │  │  Lambda / Container│   │  Lambda / Container    │ │
        │  └─────────┬──────────┘   └────────────┬───────────┘ │
        └────────────┼─────────────────────────── ┼─────────────┘
                     │                            │
                     ▼                            ▼
        ┌──────────────────────────────────────────────────────┐
        │                  DATA LAYER                           │
        │   DynamoDB     │     Redis     │   Secrets Manager   │
        └──────────────────────┬───────────────────────────────┘
                               ▼
        ┌──────────────────────────────────────────────────────┐
        │                ALERTING LAYER                         │
        │     SNS  ──▶  Slack  /  Email  /  PagerDuty          │
        └──────────────────────────────────────────────────────┘

        ┌──────────────────────────────────────────────────────┐
        │              OBSERVABILITY LAYER                      │
        │   Prometheus  ──▶  Grafana                            │
        │   OpenTelemetry  ──▶  Jaeger                          │
        └──────────────────────────────────────────────────────┘
```

---

## Tech Stack

### Application Runtime

| Component  | Technology              | Why It's Used |
|------------|-------------------------|---------------|
| Auditor    | **.NET 8 (C#)**         | Strong typing for AWS SDK calls, fast cold starts via `PublishReadyToRun`, official first-class AWS Lambda support |
| Reporter   | **Python 3.11 + Flask** | Lowest-friction web framework for the dashboard and ingestion API, plus the massive `boto3` ecosystem for AWS integration |
| Adapter    | **Mangum**              | WSGI to Lambda adapter. Lets the Flask app run identically in Lambda and in a container. One codebase, two runtimes. |

### Cloud Services (AWS)

| Service            | Purpose |
|--------------------|---------|
| **DynamoDB**       | Findings storage. NoSQL fits the time-series, write-heavy access pattern; PAY_PER_REQUEST means zero cost when idle |
| **Step Functions** | Workflow orchestration. Handles retries, branching logic, and failure paths declaratively |
| **EventBridge**    | Scheduled triggers that fire the audit pipeline every 24 hours |
| **SNS**            | Pub/sub alerting. One topic fans out to Slack, email, and PagerDuty subscribers |
| **SQS**            | Dead-letter queue for failed audits. Preserves messages for 14 days for debugging |
| **Secrets Manager**| Stores webhook URLs and credentials; fetched at runtime, cached in-process |
| **Lambda**         | Serverless compute for both Auditor and Reporter |
| **API Gateway**    | HTTPS endpoint fronting the Reporter Lambda |
| **IAM**            | Least-privilege role-based access control across every component |

### Infrastructure as Code

| Tool          | Purpose |
|---------------|---------|
| **Terraform** | Multi-cloud provisioning across AWS, Azure, and GCP. Remote state in S3 with DynamoDB locking |
| **AWS SAM**   | Single-template serverless deployment for the AWS-only path |
| **Helm**      | Templated, versioned Kubernetes deployment with rollback support |
| **Kustomize** | Raw Kubernetes manifests with environment-specific overlays |

### Containers and Orchestration

| Tool             | Purpose |
|------------------|---------|
| **Docker**       | Multi-stage builds for both services (build-time tooling stays out of runtime images) |
| **Docker Compose** | Full local development stack with services, datastores, and observability in one command |
| **Kubernetes**   | Production orchestration with HorizontalPodAutoscaler, rolling updates, and pod anti-affinity |
| **NGINX**        | Reverse proxy with rate limiting, security headers, and upstream load balancing |

### Data and Caching

| Component      | Purpose |
|----------------|---------|
| **DynamoDB**   | Primary findings store (production) |
| **Redis**      | Read-through cache for the dashboard's audit list, invalidated on every ingest |
| **PostgreSQL** | Findings store: one row per at-risk resource, queried by `/api/findings` and the dashboard's repeat-offender panel |

### Observability

### Metrics (Prometheus)

The reporter exposes `/metrics` (aggregated across all gunicorn workers).
The auditor is not scraped - it runs as a Lambda or a short-lived CronJob pod -
so it reports its scan duration and resource count to the reporter, which
exports them. Key series:

```
cloudsentinel_audits_total{provider,result}
cloudsentinel_findings_total{provider,severity}
cloudsentinel_findings_by_severity{provider,severity}    # most recent audit
cloudsentinel_scan_duration_seconds
cloudsentinel_resources_scanned_total
cloudsentinel_api_requests_total / cloudsentinel_api_request_duration_seconds
cloudsentinel_ingest_errors_total
cloudsentinel_cache_operations_total
```

In Compose, Prometheus also scrapes exporters for Redis, NGINX and PostgreSQL.

### Dashboards (Grafana)

The **CloudSentinel Overview** dashboard is provisioned automatically (Compose
and the Helm chart) and shows:

- Current posture: at-risk and critical resources in the latest audit
- Audit findings over time, by severity
- Resource scanning throughput and scan duration
- API latency percentiles (p50, p95, p99) and requests by endpoint
- Error rates by cloud provider
- Cache hit ratio, Slack delivery and findings-store writes

### Distributed Tracing (Jaeger)

Set `OTEL_EXPORTER_OTLP_ENDPOINT` (Compose points it at Jaeger) and a single
trace follows an audit from the auditor's S3 calls, through its POST to the
reporter, into DynamoDB, Redis and PostgreSQL.

---

## Security Hardening

CloudSentinel is built with defense-in-depth principles applied at every layer:

| Layer            | Controls |
|------------------|----------|
| **IAM**          | Least-privilege roles per service; no wildcard policies on sensitive resources |
| **Secrets**      | Stored in AWS Secrets Manager, Azure Key Vault, or GCP Secret Manager. Never in code or environment files |
| **Containers**   | Non-root user, `readOnlyRootFilesystem: true`, all Linux capabilities dropped, `allowPrivilegeEscalation: false` |
| **Network**      | Kubernetes NetworkPolicies, NGINX rate limiting, TLS-only ingress |
| **Transport**    | cert-manager + Let's Encrypt for automated TLS certificate management |
| **Identity**     | IRSA (IAM Roles for Service Accounts) on EKS. No static AWS credentials in pods |
| **CI Supply Chain** | Container vulnerability scanning gates deployment; SARIF reporting to GitHub Security |
| **Storage**      | S3 buckets created by Terraform have all four Public Access Block protections enabled, versioning on, AES-256 server-side encryption |

---

## License

MIT License. See [LICENSE](LICENSE) for details.
