# CloudSentinel

**Enterprise Multi-Cloud Security Governance Platform**

Automated Infrastructure-as-Code (IaC) security scanning across AWS, Azure, and GCP with containerized microservices, Kubernetes orchestration, and full observability stack.

## Architecture

```
                              ┌─────────────────────────────────────────┐
                              │           MULTI-CLOUD SCANNING          │
                              │  ┌───────┐  ┌───────┐  ┌───────┐       │
                              │  │  AWS  │  │ Azure │  │  GCP  │       │
                              │  └───┬───┘  └───┬───┘  └───┬───┘       │
                              └──────┼──────────┼──────────┼───────────┘
                                     └──────────┼──────────┘
                                                ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                              KUBERNETES CLUSTER                               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│  │   NGINX     │───▶│  Reporter   │───▶│    Redis    │    │  Prometheus │   │
│  │  Ingress    │    │   (Flask)   │    │   (Cache)   │    │  + Grafana  │   │
│  └─────────────┘    └──────┬──────┘    └─────────────┘    └─────────────┘   │
│                            │                                                  │
│                            ▼                                                  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐   │
│  │   Auditor   │───▶│  DynamoDB   │    │   Jaeger    │    │  PostgreSQL │   │
│  │  (.NET 8)   │    │  /CosmosDB  │    │  (Tracing)  │    │ (Optional)  │   │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
             ┌───────────┐   ┌───────────┐   ┌───────────┐
             │   Slack   │   │   Email   │   │  PagerDuty│
             │   Alert   │   │   (SNS)   │   │  Webhook  │
             └───────────┘   └───────────┘   └───────────┘
```

## Tech Stack

| Category | Technology | Purpose |
|----------|------------|---------|
| **IaC** | Terraform | Multi-cloud infrastructure provisioning |
| **Containers** | Docker | Application containerization |
| **Orchestration** | Kubernetes | Container orchestration & scaling |
| **Package Manager** | Helm | Kubernetes application deployment |
| **CI/CD** | GitHub Actions | Automated build, test, deploy pipeline |
| **Reverse Proxy** | NGINX | Load balancing, SSL termination |
| **Cache** | Redis | High-speed caching layer |
| **Database** | DynamoDB / CosmosDB / Firestore | Multi-cloud NoSQL storage |
| **Relational DB** | PostgreSQL | Optional relational storage |
| **Monitoring** | Prometheus | Metrics collection |
| **Dashboards** | Grafana | Visualization & alerting |
| **Tracing** | Jaeger + OpenTelemetry | Distributed tracing |
| **IaC Security** | Checkov + tfsec | Terraform security scanning |
| **Container Security** | Trivy | Vulnerability scanning |
| **Auditor** | .NET 8 (C#) | Cloud resource scanning |
| **Reporter** | Flask (Python) | REST API & Dashboard |
| **Messaging** | SNS / Service Bus / Pub/Sub | Multi-cloud alerting |

## Cloud Provider Support

| Provider | Services Scanned |
|----------|-----------------|
| **AWS** | S3, EC2, IAM, RDS, Lambda, Security Groups, VPCs |
| **Azure** | Blob Storage, VMs, RBAC, CosmosDB, Key Vault |
| **GCP** | Cloud Storage, Compute Engine, IAM, Firestore |

## Project Structure

```
CloudSentinel/
├── terraform/                    # Multi-cloud IaC
│   ├── main.tf                   # Root configuration
│   ├── variables.tf              # Input variables
│   ├── outputs.tf                # Output values
│   └── modules/
│       ├── aws/                  # AWS resources
│       ├── azure/                # Azure resources
│       └── gcp/                  # GCP resources
├── docker/                       # Container configurations
│   ├── Dockerfile.auditor        # .NET 8 container
│   ├── Dockerfile.reporter       # Python container
│   ├── nginx.conf                # Reverse proxy config
│   └── prometheus.yml            # Metrics config
├── k8s/                          # Kubernetes manifests
│   └── base/                     # Base configurations
│       ├── namespace.yaml
│       ├── configmap.yaml
│       ├── secret.yaml
│       ├── auditor-deployment.yaml
│       ├── reporter-deployment.yaml
│       ├── redis-deployment.yaml
│       ├── ingress.yaml
│       ├── hpa.yaml              # Horizontal Pod Autoscaler
│       ├── cronjob.yaml          # Scheduled audits
│       └── kustomization.yaml
├── helm/cloudsentinel/           # Helm chart
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/
├── auditor/                      # .NET 8 Lambda/Container
│   ├── Function.cs
│   └── Auditor.csproj
├── reporter/                     # Flask API
│   ├── app.py
│   ├── requirements.txt
│   └── templates/
├── .github/workflows/            # CI/CD pipeline
│   └── ci-cd.yaml
├── template.yaml                 # AWS SAM (serverless option)
├── docker-compose.yml            # Local development
└── README.md
```

## Quick Start

### Option 1: Docker Compose (Local Development)

```bash
# Clone and start all services
cp .env.example .env
docker-compose up -d

# Access services
# Dashboard:    http://localhost:8000
# Grafana:      http://localhost:3000 (admin/cloudsentinel)
# Prometheus:   http://localhost:9090
# Jaeger:       http://localhost:16686
```

### Option 2: Kubernetes (Production)

```bash
# Using Helm
helm install cloudsentinel ./helm/cloudsentinel \
  --namespace cloudsentinel \
  --create-namespace

# Using Kustomize
kubectl apply -k k8s/base/
```

### Option 3: Terraform (Multi-Cloud)

```bash
cd terraform

# Initialize
terraform init

# Preview changes
terraform plan

# Deploy (AWS only by default)
terraform apply

# Deploy multi-cloud
terraform apply \
  -var="enable_aws=true" \
  -var="enable_azure=true" \
  -var="enable_gcp=true"
```

### Option 4: AWS SAM (Serverless)

```bash
sam build
sam deploy --guided
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region | `us-east-1` |
| `DYNAMODB_TABLE` | DynamoDB table name | `SecurityAudits` |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `SLACK_WEBHOOK_URL` | Slack notifications | - |

### Terraform Variables

```hcl
# terraform.tfvars
environment = "prod"
enable_aws  = true
enable_azure = false
enable_gcp  = false
deploy_to_kubernetes = true
k8s_replicas = 3
```

## CI/CD Pipeline

The GitHub Actions workflow includes:

1. **Code Quality** - Checkov, tfsec for IaC security
2. **Build & Test** - .NET and Python tests
3. **Docker Build** - Multi-stage builds
4. **Security Scan** - Trivy container scanning
5. **Deploy** - Helm deployment to Kubernetes
6. **Terraform** - Infrastructure updates

```bash
# Trigger pipeline
git push origin main
```

## Observability

### Grafana Dashboards

Pre-configured dashboards for:
- Audit findings over time
- Resource scanning metrics
- API latency percentiles
- Error rates by cloud provider

### Prometheus Metrics

```
cloudsentinel_audits_total
cloudsentinel_findings_by_severity
cloudsentinel_scan_duration_seconds
cloudsentinel_api_requests_total
```

### Jaeger Tracing

Distributed tracing across:
- Auditor → Reporter → Database
- API Gateway → Services
- Cross-cloud operations

## Cleanup

### Docker Compose
```bash
docker-compose down -v
```

### Kubernetes
```bash
helm uninstall cloudsentinel -n cloudsentinel
kubectl delete namespace cloudsentinel
```

### Terraform
```bash
terraform destroy
```

### AWS SAM
```bash
sam delete --stack-name cloudsentinel
```

## Cost Optimization

Scale-to-zero architecture - minimal costs when idle:

| Resource | Billing Model |
|----------|--------------|
| Lambda / Cloud Run / Container Apps | Per invocation |
| DynamoDB / CosmosDB / Firestore | On-demand |
| Kubernetes (managed) | Node hours |
| Redis | Instance hours |

**Tip**: Use `docker-compose` for development to avoid cloud costs entirely.

## Security Features

- **Least Privilege IAM** - Minimal required permissions
- **Secrets Management** - AWS Secrets Manager / Azure Key Vault / GCP Secret Manager
- **Container Security** - Non-root users, read-only filesystems
- **Network Policies** - K8s network segmentation
- **TLS Everywhere** - Cert-manager + Let's Encrypt
- **RBAC** - Kubernetes role-based access control

## License

MIT License
