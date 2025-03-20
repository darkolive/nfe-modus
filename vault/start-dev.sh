#!/bin/bash

# Create data directory if it doesn't exist
mkdir -p ./data

# Start vault in development mode
./bin/vault server -dev -dev-root-token-id="dev-only-token" -dev-listen-address="127.0.0.1:8200"

# In development mode, Vault automatically:
# - Uses an in-memory storage
# - Unseals itself
# - Creates a root token "dev-only-token"
# - Enables the UI on http://127.0.0.1:8200/ui
