#############################################
# CloudSentinel - GCP Module
#############################################

variable "environment" {
  type = string
}

variable "gcp_region" {
  type = string
}

variable "gcp_project" {
  type = string
}

#############################################
# Enable Required APIs
#############################################

resource "google_project_service" "services" {
  for_each = toset([
    "run.googleapis.com",
    "firestore.googleapis.com",
    "secretmanager.googleapis.com",
    "pubsub.googleapis.com",
    "cloudscheduler.googleapis.com",
    "cloudbuild.googleapis.com"
  ])

  service            = each.key
  disable_on_destroy = false
}

#############################################
# Firestore (DynamoDB equivalent)
#############################################

resource "google_firestore_database" "cloudsentinel" {
  project     = var.gcp_project
  name        = "(default)"
  location_id = var.gcp_region
  type        = "FIRESTORE_NATIVE"

  depends_on = [google_project_service.services]
}

#############################################
# Cloud Storage (S3 equivalent)
#############################################

resource "google_storage_bucket" "reports" {
  name          = "cloudsentinel-reports-${var.gcp_project}"
  location      = var.gcp_region
  force_destroy = true

  versioning {
    enabled = true
  }

  uniform_bucket_level_access = true

  labels = {
    project     = "cloudsentinel"
    environment = var.environment
  }
}

#############################################
# Pub/Sub (SQS/SNS equivalent)
#############################################

resource "google_pubsub_topic" "security_alerts" {
  name = "cloudsentinel-security-alerts"

  labels = {
    project = "cloudsentinel"
  }
}

resource "google_pubsub_topic" "audit_queue" {
  name = "cloudsentinel-audit-queue"

  labels = {
    project = "cloudsentinel"
  }
}

resource "google_pubsub_subscription" "audit_subscription" {
  name  = "cloudsentinel-audit-subscription"
  topic = google_pubsub_topic.audit_queue.name

  ack_deadline_seconds = 60

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.audit_dlq.id
    max_delivery_attempts = 5
  }
}

resource "google_pubsub_topic" "audit_dlq" {
  name = "cloudsentinel-audit-dlq"

  labels = {
    project = "cloudsentinel"
  }
}

#############################################
# Secret Manager (Secrets Manager equivalent)
#############################################

resource "google_secret_manager_secret" "config" {
  secret_id = "cloudsentinel-config"

  replication {
    auto {}
  }

  labels = {
    project = "cloudsentinel"
  }
}

resource "google_secret_manager_secret_version" "config" {
  secret      = google_secret_manager_secret.config.id
  secret_data = jsonencode({
    webhook_url = "https://hooks.slack.com/services/PLACEHOLDER"
    environment = var.environment
  })
}

#############################################
# Cloud Run (Lambda equivalent)
#############################################

resource "google_cloud_run_service" "auditor" {
  name     = "cloudsentinel-auditor"
  location = var.gcp_region

  template {
    spec {
      containers {
        image = "gcr.io/${var.gcp_project}/cloudsentinel-auditor:latest"

        resources {
          limits = {
            cpu    = "1000m"
            memory = "512Mi"
          }
        }

        env {
          name  = "CLOUD_PROVIDER"
          value = "gcp"
        }

        env {
          name  = "GCP_PROJECT"
          value = var.gcp_project
        }
      }

      container_concurrency = 80
      timeout_seconds       = 300
    }

    metadata {
      annotations = {
        "autoscaling.knative.dev/minScale" = "0"
        "autoscaling.knative.dev/maxScale" = "10"
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [google_project_service.services]
}

resource "google_cloud_run_service" "reporter" {
  name     = "cloudsentinel-reporter"
  location = var.gcp_region

  template {
    spec {
      containers {
        image = "gcr.io/${var.gcp_project}/cloudsentinel-reporter:latest"

        resources {
          limits = {
            cpu    = "1000m"
            memory = "512Mi"
          }
        }

        env {
          name  = "GCP_PROJECT"
          value = var.gcp_project
        }

        ports {
          container_port = 8000
        }
      }
    }

    metadata {
      annotations = {
        "autoscaling.knative.dev/minScale" = "1"
        "autoscaling.knative.dev/maxScale" = "10"
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [google_project_service.services]
}

# Allow unauthenticated access to reporter (dashboard)
resource "google_cloud_run_service_iam_member" "reporter_public" {
  service  = google_cloud_run_service.reporter.name
  location = google_cloud_run_service.reporter.location
  role     = "roles/run.invoker"
  member   = "allUsers"
}

#############################################
# Cloud Scheduler (EventBridge equivalent)
#############################################

resource "google_cloud_scheduler_job" "daily_audit" {
  name        = "cloudsentinel-daily-audit"
  description = "Triggers CloudSentinel audit every 24 hours"
  schedule    = "0 0 * * *"
  time_zone   = "UTC"

  http_target {
    http_method = "POST"
    uri         = google_cloud_run_service.auditor.status[0].url

    oidc_token {
      service_account_email = google_service_account.scheduler.email
    }
  }

  depends_on = [google_project_service.services]
}

resource "google_service_account" "scheduler" {
  account_id   = "cloudsentinel-scheduler"
  display_name = "CloudSentinel Scheduler"
}

resource "google_cloud_run_service_iam_member" "scheduler_invoke" {
  service  = google_cloud_run_service.auditor.name
  location = google_cloud_run_service.auditor.location
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}

#############################################
# Outputs
#############################################

output "cloud_run_url" {
  value = google_cloud_run_service.reporter.status[0].url
}

output "firestore_database" {
  value = google_firestore_database.cloudsentinel.name
}

output "storage_bucket" {
  value = google_storage_bucket.reports.name
}

output "pubsub_topic" {
  value = google_pubsub_topic.security_alerts.name
}
