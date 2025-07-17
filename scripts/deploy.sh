#!/bin/bash

# This script deploys the application to Kubernetes.

# Apply the Kubernetes manifests.
kubectl apply -f kubernetes/manifests
