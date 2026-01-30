import pytest
from unittest.mock import patch, MagicMock
import sys
# Import your main module. 
# Make sure your main.py is importable (i.e. inside the src folder or root)
# If main.py is in the root, you might need: import main
import main 

def test_cli_help_menu(monkeypatch, capsys):
    """
    Test the interactive shell's help command.
    We simulate a user typing 'help' and then 'quit'.
    """
    # 1. Prepare the fake inputs: First 'help', then 'quit' to break the loop
    inputs = iter(['help', 'quit'])
    
    # 2. Force the code to use our fake inputs instead of real keyboard
    monkeypatch.setattr('builtins.input', lambda _: next(inputs))
    
    # 3. Run the interactive shell
    # It will process 'help', print the menu, process 'quit', and return.
    main.run_interactive_shell()
    
    # 4. Capture what was printed to the screen
    captured = capsys.readouterr()
    
    # 5. Verify the output contains the expected text
    assert "Secure Remote Storage (CLI v3.0)" in captured.out
    assert "Commands:" in captured.out
    assert "upload <file>" in captured.out

def test_cli_arg_generate():
    """
    Test the command line argument mode (Non-interactive).
    Simulates running: python main.py generate
    """
    with patch.object(sys, 'argv', ['main.py', 'generate']):
        # We also mock the perform_generate function so it doesn't actually create keys
        with patch('main.perform_generate') as mock_gen:
            main.main()
            mock_gen.assert_called_once()
