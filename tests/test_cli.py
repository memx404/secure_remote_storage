import sys
import pytest
from unittest.mock import patch
import main

def test_cli_help_menu(monkeypatch, capsys):
    """
    Verifies that the interactive shell displays the help menu and exits gracefully.
    
    Simulates a user typing 'help' followed by 'quit'.
    """
    # Simulate user input: 'help' then 'quit'
    inputs = iter(['help', 'quit'])
    monkeypatch.setattr('builtins.input', lambda _: next(inputs))

    main.run_interactive_shell()

    # Verify stdout contains help commands
    captured = capsys.readouterr()
    assert "Secure Remote Storage (CLI v3.0)" in captured.out
    assert "upload <file>" in captured.out

def test_cli_arg_generate():
    """
    Verifies that the CLI accepts 'generate' as a command-line argument.
    
    Ensures main() routes to perform_generate() without interactive input.
    """
    with patch.object(sys, 'argv', ['main.py', 'generate']):
        with patch('main.perform_generate') as mock_gen:
            main.main()
            mock_gen.assert_called_once()
