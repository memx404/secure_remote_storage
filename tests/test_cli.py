import sys
import pytest
from unittest.mock import patch
import main

def test_cli_help_menu(monkeypatch, capsys):
    """
    Verifies that the interactive shell displays the help menu and exits gracefully.
    Simulates a user typing 'help' followed by 'quit'.
    """
    # 1. Simulate user input: 'help' then 'quit'
    inputs = iter(['help', 'quit'])
    monkeypatch.setattr('builtins.input', lambda _: next(inputs))

    # 2. MOCK the server check. 
    with patch('main.perform_check_server'):
        main.run_interactive_shell()

    # 3. Verify stdout contains the correct headers and commands
    captured = capsys.readouterr()
    
    assert "Secure Remote Storage" in captured.out
    assert "HTTPS Enabled" in captured.out
    assert "upload <file>" in captured.out

def test_cli_arg_generate():
    """
    Verifies that the CLI accepts 'generate' as a command-line argument.
    Ensures main() routes to perform_generate() without interactive input.
    """
    with patch.object(sys, 'argv', ['main.py', 'generate']):
        # We also mock setup_env to avoid creating real folders during testing
        with patch('main.perform_generate') as mock_gen, \
             patch('main.setup_env'):
            
            main.main()
            mock_gen.assert_called_once()
