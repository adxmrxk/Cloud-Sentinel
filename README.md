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
| **Redis**      | Caching layer for hot reads and session data |
| **PostgreSQL** | Optional relational store available in the local Compose stack |

### Observability

| Tool                | Purpose |
|---------------------|---------|
| **Prometheus**      | Time-series metrics scraping from every service |
| **Grafana**         | Dashboards and alerting on Prometheus data |
| **Jaeger + OpenTelemetry** | Distributed tracing across the audit pipeline |

### Security and Quality

| Tool       | Purpose |
|------------|---------|
| **Checkov** | Static analysis of Terraform for misconfigurations and compliance violations |
| **tfsec**   | Terraform-specific security scanner |
| **Trivy**   | Container image vulnerability scanning |
| **cert-manager + Let's Encrypt** | Automated TLS certificate provisioning in Kubernetes |

### CI/CD

| Tool                    | Purpose |
|-------------------------|---------|
| **GitHub Actions**      | End-to-end pipeline: lint, test, scan, build, deploy |
| **GitHub Container Registry (GHCR)** | Container image hosting |
| **Codecov**             | Test coverage tracking |

---

## Project Structure

```
CloudSentinel/
│
├── auditor/                     .NET 8 scanner
│   ├── Function.cs              S3 scanning logic and severity scoring
│   ├── Auditor.csproj           .NET project, AWS SDK dependencies
│   └── aws-lambda-tools-defaults.json
│
├── reporter/                    Python Flask API and dashboard
│   ├── app.py                   POST /ingest, GET /, GET /health
│   ├── requirements.txt
│   └── templates/
│       └── dashboard.html       Jinja2 dashboard (server-rendered)
│
├── statemachine/                Step Functions workflow
│   └── audit-workflow.asl.json
│
├── terraform/                   Multi-cloud Infrastructure as Code
│   ├── main.tf                  Providers, backend, module imports
│   ├── variables.tf             Input variables with validation
│   ├── outputs.tf               Cross-cloud output values
│   └── modules/
│       ├── aws/                 DynamoDB, SQS, SNS, IAM, Step Functions, EventBridge
│       ├── azure/               CosmosDB, Service Bus, Container Apps, Key Vault
│       └── gcp/                 Firestore, Pub/Sub, Cloud Run, Secret Manager
│
├── docker/                      Container build configuration
│   ├── Dockerfile.auditor       Multi-stage .NET build
│   ├── Dockerfile.reporter      Multi-stage Python build
│   ├── nginx.conf               Reverse proxy config
│   └── prometheus.yml           Metrics scrape config
│
├── k8s/base/                    Raw Kubernetes manifests (Kustomize)
│   ├── namespace.yaml
│   ├── configmap.yaml           Non-secret environment configuration
│   ├── secret.yaml              Sensitive credentials (use ExternalSecrets in prod)
│   ├── serviceaccount.yaml      ServiceAccount, Role, and RoleBinding for IRSA
│   ├── auditor-deployment.yaml  Deployment and Service for the auditor
│   ├── reporter-deployment.yaml Deployment and Service with rolling updates
│   ├── redis-deployment.yaml    Deployment, Service, and PersistentVolumeClaim
│   ├── ingress.yaml             NGINX Ingress with TLS via cert-manager
│   ├── hpa.yaml                 HorizontalPodAutoscaler (asymmetric scale behavior)
│   ├── cronjob.yaml             Scheduled audit job (daily)
│   └── kustomization.yaml       Kustomize entry point
│
├── helm/cloudsentinel/          Helm chart (production-grade packaging)
│   ├── Chart.yaml               Metadata and subchart dependencies
│   ├── values.yaml              Configurable values
│   └── templates/
│       ├── _helpers.tpl
│       ├── auditor-deployment.yaml
│       ├── reporter-deployment.yaml
│       ├── ingress.yaml
│       ├── secrets.yaml
│       └── serviceaccount.yaml
│
├── .github/workflows/
│   └── ci-cd.yaml               Full pipeline: scan, build, test, deploy
│
├── template.yaml                AWS SAM template (serverless deployment path)
├── samconfig.toml               SAM CLI configuration
├── docker-compose.yml           Local development stack
├── .env.example                 Environment variable template
└── README.md
```

---

## Getting Started

### Prerequisites

Choose the deployment path you want, and install only the tools that path needs:

| Path             | Required Tooling |
|------------------|------------------|
| Local dev        | Docker, Docker Compose |
| AWS serverless   | AWS CLI, AWS SAM CLI, .NET 8 SDK, Python 3.11 |
| Kubernetes (raw) | `kubectl`, `kustomize` |
| Helm             | `kubectl`, Helm 3.x |
| Multi-cloud IaC  | Terraform 1.5+ |

### Quickest Start: Local Development

```bash
# Clone the repo
git clone <repo-url>
cd CloudSentinel

# Set up environment
cp .env.example .env
# (edit .env with your AWS credentials)

# Spin up the full stack
docker-compose up -d
```

That's it. Within a minute or two you'll have:

| Service     | URL                          | Login |
|-------------|------------------------------|-------|
| Dashboard   | http://localhost:8000        |       |
| Grafana     | http://localhost:3000        | `admin` / `cloudsentinel` |
| Prometheus  | http://localhost:9090        |       |
| Jaeger UI   | http://localhost:16686       |       |
| NGINX proxy | http://localhost (port 80)   |       |

### Trigger Your First Audit

The dashboard will be empty on first launch. Send a test finding to populate it:

```bash
curl -X POST http://localhost:8000/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerabilitiesFound": true,
    "totalBucketsScanned": 12,
    "atRiskBuckets": [
      {
        "BucketName": "demo-bucket",
        "Severity": "CRITICAL",
        "RiskFactors": ["NO_PUBLIC_ACCESS_BLOCK_CONFIGURED"]
      }
    ],
    "auditTimestamp": "2026-01-01T12:00:00Z"
  }'
```

Refresh http://localhost:8000 to see the finding.

### Tear Down

```bash
docker-compose down -v
```

---

## Deployment Options

CloudSentinel can be deployed four ways, each suited to a different audience:

### 1. AWS SAM (Serverless)

The fastest path for a pure-AWS deployment. Provisions DynamoDB, both Lambdas, Step Functions, EventBridge, SNS, SQS DLQ, and Secrets Manager in one stack.

```bash
sam build
sam deploy --guided
```

### 2. Kubernetes (Raw Manifests)

Deploy with Kustomize for environments where you want explicit control over every resource:

```bash
kubectl apply -k k8s/base/
```

### 3. Helm Chart

The production-recommended path for Kubernetes. Includes versioning, rollback support, and bundled subcharts for Redis, Grafana, and Prometheus.

```bash
helm install cloudsentinel ./helm/cloudsentinel \
  --namespace cloudsentinel \
  --create-namespace
```

Rollback to a previous release:

```bash
helm rollback cloudsentinel
```

### 4. Terraform (Multi-Cloud)

For organizations operating across AWS, Azure, and GCP, or for fully Infrastructure-as-Code provisioning of the entire stack (including the K8s cluster):

```bash
cd terraform

terraform init
terraform plan
terraform apply

# Multi-cloud
terraform apply \
  -var="enable_aws=true" \
  -var="enable_azure=true" \
  -var="enable_gcp=true"
```

---

## Configuration

### Environment Variables

| Variable                  | Description                              | Default                  |
|---------------------------|------------------------------------------|--------------------------|
| `AWS_REGION`              | AWS region for SDK calls                 | `us-east-1`              |
| `DYNAMODB_TABLE`          | Findings table name                      | `SecurityAudits`         |
| `DYNAMODB_ENDPOINT`       | Override for DynamoDB Local              | (uses AWS)               |
| `REDIS_URL`               | Redis connection string                  | `redis://localhost:6379` |
| `SECRET_NAME`             | Secrets Manager entry name               | `CloudSentinel/Config`   |
| `LOG_LEVEL`               | `DEBUG`, `INFO`, `WARN`, or `ERROR`      | `INFO`                   |
| `SLACK_WEBHOOK_URL`       | Slack incoming webhook for alerts        |                          |
| `PROMETHEUS_ENABLED`      | Toggle metrics endpoint                  | `true`                   |
| `JAEGER_ENABLED`          | Toggle distributed tracing               | `true`                   |
| `JAEGER_AGENT_HOST`       | Jaeger agent hostname                    | `localhost`              |

### Terraform Variables

Example `terraform.tfvars`:

```hcl
environment          = "prod"
enable_aws           = true
enable_azure         = false
enable_gcp           = false
deploy_to_kubernetes = true
k8s_replicas         = 3
```

Full variable reference in [terraform/variables.tf](terraform/variables.tf).

---

## CI/CD Pipeline

The GitHub Actions workflow ([.github/workflows/ci-cd.yaml](.github/workflows/ci-cd.yaml)) runs on every push, PR, and release:

| Stage              | Tools                            | Purpose |
|--------------------|----------------------------------|---------|
| **IaC Security**   | Checkov, tfsec                   | Static analysis of Terraform code; results uploaded as SARIF |
| **Build Auditor**  | .NET 8 SDK                       | Restore, build, test, publish |
| **Build Reporter** | Python, flake8, Black, pytest    | Lint, format check, test with coverage |
| **Build Images**   | Docker Buildx, GHCR              | Multi-tag publishing (branch, semver, sha) with layer caching |
| **Container Scan** | Trivy                            | Vulnerability scan of both images |
| **Deploy**         | Helm                             | Production deployment with rollout wait (main branch only) |
| **Terraform**      | Terraform CLI                    | Plan on every push; apply only on main |

The pipeline uses **SARIF** output so security findings land directly in GitHub's Security tab.

---

## Observability

### Metrics (Prometheus)

Every service exposes a `/metrics` endpoint that Prometheus scrapes every 15 seconds:

```
cloudsentinel_audits_total
cloudsentinel_findings_by_severity
cloudsentinel_scan_duration_seconds
cloudsentinel_api_requests_total
```

### Dashboards (Grafana)

Pre-configured dashboards visualize:

- Audit findings over time
- Resource scanning throughput
- API latency percentiles (p50, p95, p99)
- Error rates by cloud provider

### Distributed Tracing (Jaeger)

OpenTelemetry instrumentation traces requests across:

- Auditor to Reporter to DynamoDB
- API Gateway to Reporter
- Cross-cloud operations

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
