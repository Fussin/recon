terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
    gcp = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    azure = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "google" {
  project = var.gcp_project
  region  = var.gcp_region
}

provider "azurerm" {
  features {}
}

module "network" {
  source = "./modules/network"
}

module "kubernetes" {
  source = "./modules/kubernetes"
}

module "database" {
  source = "./modules/database"
}

module "security" {
  source = "./modules/security"
}

module "monitoring" {
  source = "./modules/monitoring"
}

module "storage" {
  source = "./modules/storage"
}
