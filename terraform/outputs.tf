#############################################
# CloudSentinel - Terraform Outputs
#############################################

# AWS Outputs
output "aws_dynamodb_table_arn" {
  description = "ARN of the DynamoDB table"
  value       = var.enable_aws ? module.aws[0].dynamodb_table_arn : null
}

output "aws_sqs_queue_url" {
  description = "URL of the SQS Dead Letter Queue"
  value       = var.enable_aws ? module.aws[0].sqs_queue_url : null
}

output "aws_sns_topic_arn" {
  description = "ARN of the SNS alerts topic"
  value       = var.enable_aws ? module.aws[0].sns_topic_arn : null
}

output "aws_step_function_arn" {
  description = "ARN of the Step Functions state machine"
  value       = var.enable_aws ? module.aws[0].step_function_arn : null
}

# Azure Outputs
output "azure_storage_account_name" {
  description = "Azure storage account name"
  value       = var.enable_azure ? module.azure[0].storage_account_name : null
}

output "azure_cosmosdb_endpoint" {
  description = "Azure CosmosDB endpoint"
  value       = var.enable_azure ? module.azure[0].cosmosdb_endpoint : null
}

# GCP Outputs
output "gcp_cloud_run_url" {
  description = "GCP Cloud Run service URL"
  value       = var.enable_gcp ? module.gcp[0].cloud_run_url : null
}

output "gcp_firestore_database" {
  description = "GCP Firestore database name"
  value       = var.enable_gcp ? module.gcp[0].firestore_database : null
}

# Kubernetes Outputs
output "k8s_namespace" {
  description = "Kubernetes namespace"
  value       = var.deploy_to_kubernetes ? kubernetes_namespace.cloudsentinel[0].metadata[0].name : null
}

output "dashboard_url" {
  description = "CloudSentinel dashboard URL"
  value       = var.deploy_to_kubernetes ? "http://cloudsentinel.local" : (var.enable_aws ? module.aws[0].api_gateway_url : null)
}
