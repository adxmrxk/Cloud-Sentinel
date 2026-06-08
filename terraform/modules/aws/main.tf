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
    name = "severity"
    type = "S"
  }

  global_secondary_index {
    name            = "SeverityIndex"
    hash_key        = "severity"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
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

  tags = {
    Name = "CloudSentinel-DLQ"
  }
}

resource "aws_sqs_queue" "audit_queue" {
  name                       = "cloudsentinel-audit-queue"
  visibility_timeout_seconds = 60
  message_retention_seconds  = 86400

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
  name         = "cloudsentinel-security-alerts"
  display_name = "CloudSentinel Security Alerts"

  tags = {
    Name = "CloudSentinel-Alerts"
  }
}

#############################################
# Secrets Manager
#############################################

resource "aws_secretsmanager_secret" "config" {
  name        = "cloudsentinel/config"
  description = "CloudSentinel configuration"

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
  name = "cloudsentinel-auditor-policy"
  role = aws_iam_role.auditor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketLocation",
          "s3:GetBucketEncryption",
          "s3:GetBucketVersioning"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVolumes",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:ListPolicies",
          "iam:GetAccountPasswordPolicy",
          "iam:ListMFADevices",
          "iam:ListAccessKeys"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions",
          "lambda:GetFunctionConfiguration"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

#############################################
# Step Functions
#############################################

resource "aws_sfn_state_machine" "audit_workflow" {
  name     = "cloudsentinel-audit-workflow"
  role_arn = aws_iam_role.step_functions.arn

  definition = jsonencode({
    Comment = "CloudSentinel Multi-Cloud Audit Workflow"
    StartAt = "ParallelAudit"
    States = {
      ParallelAudit = {
        Type = "Parallel"
        Branches = [
          {
            StartAt = "AuditAWS"
            States = {
              AuditAWS = {
                Type     = "Task"
                Resource = "arn:aws:states:::lambda:invoke"
                Parameters = {
                  FunctionName = "cloudsentinel-auditor"
                  Payload = {
                    "cloud"    = "aws"
                    "input.$"  = "$"
                  }
                }
                End = true
              }
            }
          }
        ]
        Next = "ProcessResults"
      }
      ProcessResults = {
        Type     = "Task"
        Resource = "arn:aws:states:::lambda:invoke"
        Parameters = {
          FunctionName = "cloudsentinel-reporter"
          Payload = {
            "results.$" = "$"
          }
        }
        Next = "CheckFindings"
      }
      CheckFindings = {
        Type = "Choice"
        Choices = [{
          Variable      = "$.Payload.vulnerabilitiesFound"
          BooleanEquals = true
          Next          = "SendAlert"
        }]
        Default = "AuditComplete"
      }
      SendAlert = {
        Type     = "Task"
        Resource = "arn:aws:states:::sns:publish"
        Parameters = {
          TopicArn = aws_sns_topic.security_alerts.arn
          Subject  = "CloudSentinel: Security Issues Detected"
          "Message.$" = "$.Payload.summary"
        }
        Next = "AuditComplete"
      }
      AuditComplete = {
        Type = "Succeed"
      }
    }
  })
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

resource "aws_iam_role_policy" "step_functions" {
  name = "cloudsentinel-stepfunctions-policy"
  role = aws_iam_role.step_functions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = aws_sns_topic.security_alerts.arn
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

output "api_gateway_url" {
  value = "https://cloudsentinel.execute-api.${var.aws_region}.amazonaws.com/prod"
}
