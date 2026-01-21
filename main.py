import os
# Import the refactored modules from the src package
from src import keys, crypto

# Centralized configuration for directory paths
DIRECTORIES = {
    "keys": "keys",
    "input": "test_inputs",
    "output": "test_outputs",
    "restored": "test_restored"
}
