"""
Compatibility shim for tests/CI.

Some test files import `app` (import app).
This file makes both patterns work.
"""
from server.app import app 