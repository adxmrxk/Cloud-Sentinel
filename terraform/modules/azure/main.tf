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
  # checkov:skip=CKV_AZURE_100:Customer-managed keys are an organisational key-management decision; Microsoft-managed encryption at rest is on by default.
  # checkov:skip=CKV_AZURE_101:Disabling public network access requires a private endpoint; private networking needs a VNet and private DNS design that this module does not define; decide it per environment.
  # checkov:skip=CKV_AZURE_99:Network restriction requires a VNet rule or IP allow-list; private networking needs a VNet and private DNS design that this module does not define; decide it per environment.
  name                = "cloudsentinel-cosmos-${var.environment}"
  location            = azurerm_resource_group.cloudsentinel.location
  resource_group_name = azurerm_resource_group.cloudsentinel.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  # Data-plane access through Entra ID RBAC only; no account keys, and keys
  # cannot be used to change account metadata.
  local_authentication_disabled      = true
  access_key_metadata_writes_enabled = false

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
  # checkov:skip=CKV_AZURE_59:Disabling public network access requires a private endpoint; private networking needs a VNet and private DNS design that this module does not define; decide it per environment.
  # checkov:skip=CKV2_AZURE_33:private networking needs a VNet and private DNS design that this module does not define; decide it per environment.
  # checkov:skip=CKV2_AZURE_1:Customer-managed keys are an organisational key-management decision; Microsoft-managed encryption at rest is on by default.
  name                     = "cloudsentinel${var.environment}"
  resource_group_name      = azurerm_resource_group.cloudsentinel.name
  location                 = azurerm_resource_group.cloudsentinel.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false

  sas_policy {
    expiration_period = "01.00:00:00"
    expiration_action = "Log"
  }

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 7
    }

    container_delete_retention_policy {
      days = 7
    }
  }

  queue_properties {
    logging {
      delete                = true
      read                  = true
      write                 = true
      version               = "1.0"
      retention_policy_days = 30
    }
  }

  tags = {
    Project = "CloudSentinel"
  }
}

resource "azurerm_storage_container" "reports" {
  # checkov:skip=CKV2_AZURE_21:Log Analytics Storage Insights needs the storage account key, which this account disables; use an Azure Monitor diagnostic setting for blob read logs.
  name                  = "reports"
  storage_account_name  = azurerm_storage_account.cloudsentinel.name
  container_access_type = "private"
}

#############################################
# Service Bus (SQS/SNS equivalent)
#############################################

resource "azurerm_servicebus_namespace" "cloudsentinel" {
  # checkov:skip=CKV_AZURE_199:Infrastructure double encryption requires the Premium SKU.
  # checkov:skip=CKV_AZURE_201:Customer-managed keys require the Premium SKU.
  # checkov:skip=CKV_AZURE_204:Disabling public network access requires Premium private endpoints; private networking needs a VNet and private DNS design that this module does not define; decide it per environment.
  name                = "cloudsentinel-sb-${var.environment}"
  location            = azurerm_resource_group.cloudsentinel.location
  resource_group_name = azurerm_resource_group.cloudsentinel.name
  sku                 = "Standard"

  minimum_tls_version = "1.2"
  local_auth_enabled  = false

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Project = "CloudSentinel"
  }
}

resource "azurerm_servicebus_queue" "audit_queue" {
  name         = "audit-queue"
  namespace_id = azurerm_servicebus_namespace.cloudsentinel.id

  partitioning_enabled                 = false
  max_delivery_count                   = 3
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
  # checkov:skip=CKV_AZURE_189:Disabling public network access requires a private endpoint; private networking needs a VNet and private DNS design that this module does not define; decide it per environment. The firewall below denies everything except trusted Azure services.
  # checkov:skip=CKV2_AZURE_32:private networking needs a VNet and private DNS design that this module does not define; decide it per environment.
  name                = "cloudsentinel-kv-${var.environment}"
  location            = azurerm_resource_group.cloudsentinel.location
  resource_group_name = azurerm_resource_group.cloudsentinel.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  purge_protection_enabled   = true
  soft_delete_retention_days = 90

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }

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
      image  = "ghcr.io/adxmrxk/cloudsentinel-auditor:latest"
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
      image  = "ghcr.io/adxmrxk/cloudsentinel-reporter:latest"
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
