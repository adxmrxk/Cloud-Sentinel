#############################################
# CloudSentinel - Azure Module
#############################################

variable "environment" {
  type = string
}

variable "azure_location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

#############################################
# Resource Group
#############################################

resource "azurerm_resource_group" "cloudsentinel" {
  name     = var.resource_group_name
  location = var.azure_location

  tags = {
    Project     = "CloudSentinel"
    Environment = var.environment
  }
}

#############################################
# CosmosDB (DynamoDB equivalent)
#############################################

resource "azurerm_cosmosdb_account" "cloudsentinel" {
  name                = "cloudsentinel-cosmos-${var.environment}"
  location            = azurerm_resource_group.cloudsentinel.location
  resource_group_name = azurerm_resource_group.cloudsentinel.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.cloudsentinel.location
    failover_priority = 0
  }

  capabilities {
    name = "EnableServerless"
  }

  tags = {
    Project = "CloudSentinel"
  }
}

resource "azurerm_cosmosdb_sql_database" "audits" {
  name                = "SecurityAudits"
  resource_group_name = azurerm_resource_group.cloudsentinel.name
  account_name        = azurerm_cosmosdb_account.cloudsentinel.name
}

resource "azurerm_cosmosdb_sql_container" "findings" {
  name                = "Findings"
  resource_group_name = azurerm_resource_group.cloudsentinel.name
  account_name        = azurerm_cosmosdb_account.cloudsentinel.name
  database_name       = azurerm_cosmosdb_sql_database.audits.name
  partition_key_paths = ["/auditId"]
}

#############################################
# Storage Account (S3 equivalent)
#############################################

resource "azurerm_storage_account" "cloudsentinel" {
  name                     = "cloudsentinel${var.environment}"
  resource_group_name      = azurerm_resource_group.cloudsentinel.name
  location                 = azurerm_resource_group.cloudsentinel.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  blob_properties {
    versioning_enabled = true
  }

  tags = {
    Project = "CloudSentinel"
  }
}

resource "azurerm_storage_container" "reports" {
  name                  = "reports"
  storage_account_name  = azurerm_storage_account.cloudsentinel.name
  container_access_type = "private"
}

#############################################
# Service Bus (SQS/SNS equivalent)
#############################################

resource "azurerm_servicebus_namespace" "cloudsentinel" {
  name                = "cloudsentinel-sb-${var.environment}"
  location            = azurerm_resource_group.cloudsentinel.location
  resource_group_name = azurerm_resource_group.cloudsentinel.name
  sku                 = "Standard"

  tags = {
    Project = "CloudSentinel"
  }
}

resource "azurerm_servicebus_queue" "audit_queue" {
  name         = "audit-queue"
  namespace_id = azurerm_servicebus_namespace.cloudsentinel.id

  enable_partitioning   = false
  max_delivery_count    = 3
  dead_lettering_on_message_expiration = true
}

resource "azurerm_servicebus_topic" "alerts" {
  name         = "security-alerts"
  namespace_id = azurerm_servicebus_namespace.cloudsentinel.id
}

#############################################
# Key Vault (Secrets Manager equivalent)
#############################################

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "cloudsentinel" {
  name                = "cloudsentinel-kv-${var.environment}"
  location            = azurerm_resource_group.cloudsentinel.location
  resource_group_name = azurerm_resource_group.cloudsentinel.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get", "List", "Set", "Delete"
    ]
  }

  tags = {
    Project = "CloudSentinel"
  }
}

#############################################
# Container Apps (Lambda equivalent)
#############################################

resource "azurerm_container_app_environment" "cloudsentinel" {
  name                = "cloudsentinel-env"
  location            = azurerm_resource_group.cloudsentinel.location
  resource_group_name = azurerm_resource_group.cloudsentinel.name

  tags = {
    Project = "CloudSentinel"
  }
}

resource "azurerm_container_app" "auditor" {
  name                         = "cloudsentinel-auditor"
  container_app_environment_id = azurerm_container_app_environment.cloudsentinel.id
  resource_group_name          = azurerm_resource_group.cloudsentinel.name
  revision_mode                = "Single"

  template {
    container {
      name   = "auditor"
      image  = "cloudsentinel/auditor:latest"
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "CLOUD_PROVIDER"
        value = "azure"
      }
    }
    min_replicas = 0
    max_replicas = 5
  }

  tags = {
    Project = "CloudSentinel"
  }
}

resource "azurerm_container_app" "reporter" {
  name                         = "cloudsentinel-reporter"
  container_app_environment_id = azurerm_container_app_environment.cloudsentinel.id
  resource_group_name          = azurerm_resource_group.cloudsentinel.name
  revision_mode                = "Single"

  template {
    container {
      name   = "reporter"
      image  = "cloudsentinel/reporter:latest"
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "COSMOSDB_ENDPOINT"
        value = azurerm_cosmosdb_account.cloudsentinel.endpoint
      }
    }
    min_replicas = 1
    max_replicas = 10
  }

  ingress {
    external_enabled = true
    target_port      = 8000
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }

  tags = {
    Project = "CloudSentinel"
  }
}

#############################################
# Outputs
#############################################

output "storage_account_name" {
  value = azurerm_storage_account.cloudsentinel.name
}

output "cosmosdb_endpoint" {
  value = azurerm_cosmosdb_account.cloudsentinel.endpoint
}

output "keyvault_uri" {
  value = azurerm_key_vault.cloudsentinel.vault_uri
}

output "reporter_url" {
  value = azurerm_container_app.reporter.latest_revision_fqdn
}
