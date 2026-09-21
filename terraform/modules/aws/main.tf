#############################################
# CloudSentinel - AWS Module
#############################################

variable "environment" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "dynamodb_table" {
  type = string
}

# Terraform does not build the Lambda functions; the SAM template does
# (template.yaml). The state machine invokes them by these names.
variable "auditor_function_name" {
  type    = string
  default = "CloudSentinel-Auditor"
}

variable "reporter_function_name" {
  type    = string
  default = "CloudSentinel-Reporter"
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  auditor_function_arn  = "arn:${local.partition}:lambda:${var.aws_region}:${local.account_id}:function:${var.auditor_function_name}"
  reporter_function_arn = "arn:${local.partition}:lambda:${var.aws_region}:${local.account_id}:function:${var.reporter_function_name}"
}

#############################################
# KMS key for CloudSentinel data at rest
# (DynamoDB, SNS, SQS, Secrets Manager, CloudWatch Logs)
#############################################

resource "aws_kms_key" "data" {
  description             = "CloudSentinel data encryption (${var.environment})"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdministration"
        Effect    = "Allow"
        Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AwsServicesInThisAccount"
        Effect    = "Allow"
        Principal = { Service = ["sns.amazonaws.com", "sqs.amazonaws.com", "events.amazonaws.com", "states.amazonaws.com"] }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
        Condition = { StringEquals = { "aws:SourceAccount" = local.account_id } }
      },
      {
        Sid       = "CloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action    = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = {
          ArnLike = { "kms:EncryptionContext:aws:logs:arn" = "arn:${local.partition}:logs:${var.aws_region}:${local.account_id}:*" }
        }
      }
    ]
  })

  tags = {
    Name = "CloudSentinel-Data-KMS"
  }
}

resource "aws_kms_alias" "data" {
  name          = "alias/cloudsentinel-data-${var.environment}"
  target_key_id = aws_kms_key.data.key_id
}

#############################################
# DynamoDB Table
#############################################

resource "aws_dynamodb_table" "security_audits" {
  name         = var.dynamodb_table
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "auditId"
  range_key    = "timestamp"

  attribute {
    name = "auditId"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  attribute {
    name = "recordType"
    type = "S"
  }

  # Newest-first paging for the dashboard. Replaces SeverityIndex: audits
  # never had a top-level severity attribute, so that index was always empty.
  global_secondary_index {
    name            = "byTimestamp"
    hash_key        = "recordType"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.data.arn
  }

  tags = {
    Name = "CloudSentinel-SecurityAudits"
  }
}

#############################################
# SQS Dead Letter Queue
#############################################

resource "aws_sqs_queue" "audit_dlq" {
  name                      = "cloudsentinel-audit-dlq"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = aws_kms_key.data.arn

  tags = {
    Name = "CloudSentinel-DLQ"
  }
}

resource "aws_sqs_queue" "audit_queue" {
  name                       = "cloudsentinel-audit-queue"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 86400
  kms_master_key_id          = aws_kms_key.data.arn

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.audit_dlq.arn
    maxReceiveCount     = 3
  })

  tags = {
    Name = "CloudSentinel-AuditQueue"
  }
}

#############################################
# SNS Topic
#############################################

resource "aws_sns_topic" "security_alerts" {
  name              = "cloudsentinel-security-alerts"
  display_name      = "CloudSentinel Security Alerts"
  kms_master_key_id = aws_kms_key.data.arn

  tags = {
    Name = "CloudSentinel-Alerts"
  }
}

#############################################
# Secrets Manager
#############################################

resource "aws_secretsmanager_secret" "config" {
  # checkov:skip=CKV2_AWS_57:The secret holds a Slack incoming-webhook URL. Slack issues it and offers no API to rotate it, so a rotation function would have nothing to call.
  name        = "cloudsentinel/config"
  description = "CloudSentinel configuration"
  kms_key_id  = aws_kms_key.data.arn

  tags = {
    Name = "CloudSentinel-Config"
  }
}

resource "aws_secretsmanager_secret_version" "config" {
  secret_id = aws_secretsmanager_secret.config.id
  secret_string = jsonencode({
    webhook_url = "https://hooks.slack.com/services/PLACEHOLDER"
    environment = var.environment
  })
}

#############################################
# KMS Key for Reports Bucket Encryption
#############################################

resource "aws_kms_key" "reports" {
  description             = "KMS key for CloudSentinel reports bucket encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AccountAdministration"
      Effect    = "Allow"
      Principal = { AWS = "arn:${local.partition}:iam::${local.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })

  tags = {
    Name = "CloudSentinel-Reports-KMS"
  }
}

resource "aws_kms_alias" "reports" {
  name          = "alias/cloudsentinel-reports-${var.environment}"
  target_key_id = aws_kms_key.reports.key_id
}

#############################################
# S3 Bucket for Reports
#############################################

resource "aws_s3_bucket" "reports" {
  # checkov:skip=CKV_AWS_144:Cross-region replication adds substantial cost and is not required for non-critical audit reports; findings of record live in DynamoDB.
  # checkov:skip=CKV2_AWS_62:S3 event notifications are not used; downstream consumers read findings from DynamoDB, not from S3 object events.
  bucket = "cloudsentinel-reports-${var.environment}-${random_id.bucket_suffix.hex}"

  tags = {
    Name = "CloudSentinel-Reports"
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_logging" "reports" {
  bucket        = aws_s3_bucket.reports.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "reports/"
}

# Destination for S3 server access logs.
#tfsec:ignore:aws-s3-enable-bucket-logging This is the access-log destination; logging it to itself would loop.
resource "aws_s3_bucket" "access_logs" {
  # checkov:skip=CKV_AWS_18:This is the access-log destination; logging it to itself would loop.
  # checkov:skip=CKV_AWS_144:Cross-region replication of access logs is not required for this project.
  # checkov:skip=CKV2_AWS_62:No consumers subscribe to access-log object events.
  # checkov:skip=CKV_AWS_145:S3 server access logging only supports SSE-S3 destination buckets, not SSE-KMS.
  bucket = "cloudsentinel-access-logs-${var.environment}-${random_id.bucket_suffix.hex}"

  tags = {
    Name = "CloudSentinel-AccessLogs"
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

#tfsec:ignore:aws-s3-encryption-customer-key S3 server access logging only supports SSE-S3 destination buckets, not SSE-KMS.
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-access-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "S3ServerAccessLogsPolicy"
      Effect    = "Allow"
      Principal = { Service = "logging.s3.amazonaws.com" }
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.access_logs.arn}/*"
      Condition = {
        ArnLike      = { "aws:SourceArn" = aws_s3_bucket.reports.arn }
        StringEquals = { "aws:SourceAccount" = local.account_id }
      }
    }]
  })
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.reports.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "archive-and-expire"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER"
    }

    expiration {
      days = 365
    }

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

#############################################
# IAM Roles
#############################################

# Auditor Lambda Role
resource "aws_iam_role" "auditor" {
  name = "cloudsentinel-auditor-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "auditor" {
  # checkov:skip=CKV_AWS_355:s3:ListAllMyBuckets has no resource-level permissions; AWS only accepts "*" for it. Every other action is scoped.
  name = "cloudsentinel-auditor-policy"
  role = aws_iam_role.auditor.id

  # Exactly the calls Function.cs makes. The previous policy also granted
  # EC2, IAM, RDS and Lambda read access that no code used.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListBuckets"
        Effect   = "Allow"
        Action   = "s3:ListAllMyBuckets"
        Resource = "*"
      },
      {
        Sid    = "ReadBucketExposure"
        Effect = "Allow"
        Action = [
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketPolicy",
          "s3:GetBucketAcl"
        ]
        Resource = "arn:${local.partition}:s3:::*"
      },
      {
        Sid    = "Logs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:${local.partition}:logs:${var.aws_region}:${local.account_id}:log-group:/aws/lambda/${var.auditor_function_name}:*"
      }
    ]
  })
}

#############################################
# Step Functions
#############################################

resource "aws_cloudwatch_log_group" "audit_workflow" {
  name              = "/aws/vendedlogs/states/cloudsentinel-audit-workflow"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_sfn_state_machine" "audit_workflow" {
  name     = "cloudsentinel-audit-workflow"
  role_arn = aws_iam_role.step_functions.arn

  # The same definition the SAM template deploys. This module used to carry
  # its own inline copy that invoked functions Terraform never creates and
  # sent the reporter a payload it could not route.
  definition = templatefile("${path.module}/../../../statemachine/audit-workflow.asl.json", {
    AuditorFunctionArn     = local.auditor_function_arn
    ReporterFunctionArn    = local.reporter_function_arn
    SecurityAlertsTopicArn = aws_sns_topic.security_alerts.arn
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.audit_workflow.arn}:*"
    include_execution_data = true
    level                  = "ERROR"
  }

  tracing_configuration {
    enabled = true
  }
}

resource "aws_iam_role" "step_functions" {
  name = "cloudsentinel-stepfunctions-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "states.amazonaws.com"
      }
    }]
  })
}

# Log delivery and X-Ray APIs have no resource-level permissions.
#tfsec:ignore:aws-iam-no-policy-wildcards CloudWatch Logs delivery and X-Ray actions only accept "*" as the resource.
resource "aws_iam_role_policy" "step_functions_observability" {
  # checkov:skip=CKV_AWS_355:CloudWatch Logs delivery and X-Ray actions only accept "*" as the resource.
  # checkov:skip=CKV_AWS_290:CloudWatch Logs delivery and X-Ray actions only accept "*" as the resource.
  name = "cloudsentinel-stepfunctions-observability"
  role = aws_iam_role.step_functions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogDelivery",
          "logs:GetLogDelivery",
          "logs:UpdateLogDelivery",
          "logs:DeleteLogDelivery",
          "logs:ListLogDeliveries",
          "logs:PutResourcePolicy",
          "logs:DescribeResourcePolicies",
          "logs:DescribeLogGroups"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
          "xray:GetSamplingRules",
          "xray:GetSamplingTargets"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "step_functions" {
  name = "cloudsentinel-stepfunctions-policy"
  role = aws_iam_role.step_functions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = [local.auditor_function_arn, local.reporter_function_arn]
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.data.arn
      }
    ]
  })
}

#############################################
# EventBridge Rule
#############################################

resource "aws_cloudwatch_event_rule" "daily_audit" {
  name                = "cloudsentinel-daily-audit"
  description         = "Triggers CloudSentinel audit every 24 hours"
  schedule_expression = "rate(24 hours)"
}

resource "aws_cloudwatch_event_target" "step_function" {
  rule     = aws_cloudwatch_event_rule.daily_audit.name
  arn      = aws_sfn_state_machine.audit_workflow.arn
  role_arn = aws_iam_role.eventbridge.arn
}

resource "aws_iam_role" "eventbridge" {
  name = "cloudsentinel-eventbridge-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "events.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge" {
  name = "cloudsentinel-eventbridge-policy"
  role = aws_iam_role.eventbridge.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = aws_sfn_state_machine.audit_workflow.arn
    }]
  })
}

#############################################
# Outputs
#############################################

output "dynamodb_table_arn" {
  value = aws_dynamodb_table.security_audits.arn
}

output "sqs_queue_url" {
  value = aws_sqs_queue.audit_queue.url
}

output "sns_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}

output "step_function_arn" {
  value = aws_sfn_state_machine.audit_workflow.arn
}

# The dashboard URL is the DashboardUrl output of the SAM stack
# (template.yaml), which owns the API Gateway. This module used to output a
# hard-coded URL here that pointed at nothing.
