#############################################
# CloudSentinel - Multi-Cloud Terraform
# Supports: AWS, Azure, GCP
#############################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.11"
    }
  }

  # Remote state storage (S3/Azure Blob/GCS)
  backend "s3" {
    bucket         = "cloudsentinel-terraform-state"
    key            = "state/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "cloudsentinel-terraform-locks"
  }
}

#############################################
# Provider Configurations
#############################################

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CloudSentinel"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
  subscription_id = var.azure_subscription_id
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig_path
  }
}

#############################################
# Module Imports
#############################################

module "aws" {
  source = "./modules/aws"
  count  = var.enable_aws ? 1 : 0

  environment    = var.environment
  aws_region     = var.aws_region
  dynamodb_table = var.dynamodb_table_name
}

module "azure" {
  source = "./modules/azure"
  count  = var.enable_azure ? 1 : 0

  environment         = var.environment
  azure_location      = var.azure_location
  resource_group_name = var.azure_resource_group
}

module "gcp" {
  source = "./modules/gcp"
  count  = var.enable_gcp ? 1 : 0

  environment = var.environment
  gcp_region  = var.gcp_region
  gcp_project = var.gcp_project_id
}

#############################################
# Kubernetes Deployment
#############################################

resource "kubernetes_namespace" "cloudsentinel" {
  count = var.deploy_to_kubernetes ? 1 : 0

  metadata {
    name = "cloudsentinel"

    labels = {
      app         = "cloudsentinel"
      environment = var.environment
    }
  }
}

resource "helm_release" "cloudsentinel" {
  count = var.deploy_to_kubernetes ? 1 : 0

  name       = "cloudsentinel"
  namespace  = kubernetes_namespace.cloudsentinel[0].metadata[0].name
  chart      = "../helm/cloudsentinel"

  values = [
    templatefile("${path.module}/helm-values.yaml", {
      environment    = var.environment
      replicas       = var.k8s_replicas
      image_tag      = var.image_tag
      dynamodb_table = var.dynamodb_table_name
    })
  ]

  depends_on = [kubernetes_namespace.cloudsentinel]
}
