import subprocess
import os
import sys
import pytest

# Helper: We wrap the subprocess call to make tests cleaner
def run_cli(args):
    """Runs the main.py script with the given list of arguments."""
    cmd = [sys.executable, "main.py"] + args
    # capture_output=True allows us to check what was printed to the screen
    return subprocess.run(cmd, capture_output=True, text=True)

def test_cli_help_menu():
    """Verify that the help menu is accessible and displays usage info."""
    result = run_cli(["--help"])
    assert result.returncode == 0
    assert "usage:" in result.stdout

def test_cli_generation_command():
    """Verify that the 'generate' command executes without crashing."""
    result = run_cli(["generate"])
    assert result.returncode == 0
    assert "Identity generated" in result.stdout

def test_cli_encryption_missing_arg():
    """Ensure the tool fails gracefully if --file is missing."""
    result = run_cli(["encrypt"])
    # Argparse usually returns code 2 for bad arguments
    assert result.returncode != 0 
    assert "required" in result.stderr