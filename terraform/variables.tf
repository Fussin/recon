variable "aws_region" {
  description = "The AWS region to deploy to."
  default     = "us-east-1"
}

variable "gcp_project" {
  description = "The GCP project to deploy to."
}

variable "gcp_region" {
  description = "The GCP region to deploy to."
  default     = "us-central1"
}

variable "env" {
  description = "The environment to deploy to."
  default     = "dev"
}

variable "instance_size" {
  description = "The size of the instances to deploy."
  default     = "t2.micro"
}

variable "vpc_cidr" {
  description = "The CIDR block for the VPC."
  default     = "10.0.0.0/16"
}

variable "db_name" {
  description = "The name of the database."
  default     = "autonomouspen"
}

variable "db_user" {
  description = "The username for the database."
  default     = "autonomouspen"
}

variable "db_password" {
  description = "The password for the database."
}

variable "k8s_version" {
  description = "The version of Kubernetes to use."
  default     = "1.21"
}
