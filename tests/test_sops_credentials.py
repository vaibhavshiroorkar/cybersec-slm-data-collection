import os
import subprocess
from unittest import mock
import pytest
from tools.check_credential_expiry import main, WARN_DAYS_BEFORE
import datetime as dt

def test_sops_decryption_core(monkeypatch):
    """Test that core.py invokes sops and sets environ appropriately."""
    import importlib
    import cybersec_slm.core as core
    
    mock_run = mock.Mock()
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = "test_source:\n  env: TEST_KEY\n  value: 'secret123'"
    
    monkeypatch.setattr(subprocess, "run", mock_run)
    monkeypatch.setattr(os.path, "exists", lambda p: True)
    
    # Reload the module to trigger the top-level SOPS code
    importlib.reload(core)
        
    assert os.environ.get("TEST_KEY") == "secret123"


def test_check_credential_expiry_all_ok(monkeypatch, capsys):
    """Test check_credential_expiry when all credentials are far from expiry."""
    import yaml
    
    future = (dt.date.today() + dt.timedelta(days=WARN_DAYS_BEFORE + 10)).isoformat()
    mock_yaml = f"test:\n  env: KEY\n  expires_at: '{future}'"
    
    mock_run = mock.Mock()
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = mock_yaml
    
    monkeypatch.setattr(os.path, "exists", lambda p: True)
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    assert main() == 0
    out, err = capsys.readouterr()
    assert "All credentials are fine." in out
    assert "ok    - test: expires" in out


def test_check_credential_expiry_needs_rotation(monkeypatch, capsys):
    """Test check_credential_expiry when a credential is close to expiry."""
    import yaml
    
    soon = (dt.date.today() + dt.timedelta(days=WARN_DAYS_BEFORE - 1)).isoformat()
    mock_yaml = f"test:\n  env: KEY\n  expires_at: '{soon}'"
    
    mock_run = mock.Mock()
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = mock_yaml
    
    monkeypatch.setattr(os.path, "exists", lambda p: True)
    monkeypatch.setattr(subprocess, "run", mock_run)
    
    assert main() == 1
    out, err = capsys.readouterr()
    assert "credential(s) need rotation" in out
    assert "ACTION - test: expires in" in out
