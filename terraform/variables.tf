#############################################
# CloudSentinel - Terraform Variables
#############################################

# General
variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

#############################################
# AWS Configuration
#############################################

variable "enable_aws" {
  description = "Enable AWS resources"
  type        = bool
  default     = true
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "dynamodb_table_name" {
  description = "DynamoDB table name for audit findings"
  type        = string
  default     = "SecurityAudits"
}

#############################################
# Azure Configuration
#############################################

variable "enable_azure" {
  description = "Enable Azure resources"
  type        = bool
  default     = false
}

variable "azure_subscription_id" {
  description = "Azure subscription ID"
  type        = string
  default     = ""
}

variable "azure_location" {
  description = "Azure region"
  type        = string
  default     = "East US"
}

variable "azure_resource_group" {
  description = "Azure resource group name"
  type        = string
  default     = "cloudsentinel-rg"
}

#############################################
# GCP Configuration
#############################################

variable "enable_gcp" {
  description = "Enable GCP resources"
  type        = bool
  default     = false
}

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

#############################################
# Kubernetes Configuration
#############################################

variable "deploy_to_kubernetes" {
  description = "Deploy CloudSentinel to Kubernetes"
  type        = bool
  default     = false
}

variable "kubeconfig_path" {
  description = "Path to kubeconfig file"
  type        = string
  default     = "~/.kube/config"
}

variable "k8s_replicas" {
  description = "Number of pod replicas"
  type        = number
  default     = 2
}

variable "image_tag" {
  description = "Docker image tag"
  type        = string
  default     = "latest"
}
