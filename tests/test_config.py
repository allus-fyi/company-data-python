"""Config loader tests."""

import json

import pytest

from allus_company_data.config import Config, ConfigError


def _write(tmp_path, data):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return str(p)


def _full(tmp_path):
    return {
        "api_url": "https://api.allme.fyi",
        "client_id": "svc_abc",
        "client_secret": "file-secret",
        "service_private_key": "./service-CRM.pem",
        "key_passphrase": "file-passphrase",
        "account_private_key": "./account.pem",
        "account_passphrase": "acct-pass",
        "webhooks": {"wh_1": "secret-one", "wh_2": "secret-two"},
        "cache_dir": "./allus-cache",
        "format": "json",
    }


def test_from_file_loads_all_fields(tmp_path):
    cfg = Config.from_file(_write(tmp_path, _full(tmp_path)))
    assert cfg.api_url == "https://api.allme.fyi"
    assert cfg.client_id == "svc_abc"
    assert cfg.client_secret == "file-secret"
    assert cfg.service_private_key == "./service-CRM.pem"
    assert cfg.key_passphrase == "file-passphrase"
    assert cfg.account_private_key == "./account.pem"
    assert cfg.account_passphrase == "acct-pass"
    assert cfg.cache_dir == "./allus-cache"
    assert cfg.format == "json"
    assert cfg.webhook_secret("wh_1") == "secret-one"
    assert cfg.webhook_secret("wh_2") == "secret-two"


def test_optional_fields_default(tmp_path):
    data = {
        "api_url": "https://api.allme.fyi",
        "client_id": "svc_abc",
        "client_secret": "s",
        "service_private_key": "./k.pem",
        "key_passphrase": "p",
    }
    cfg = Config.from_file(_write(tmp_path, data))
    assert cfg.account_private_key is None
    assert cfg.account_passphrase is None
    assert cfg.webhooks == {}
    assert cfg.cache_dir == "./allus-cache"  # default
    assert cfg.format == "json"              # default


def test_env_overrides_file_values(tmp_path, monkeypatch):
    path = _write(tmp_path, _full(tmp_path))
    monkeypatch.setenv("ALLUS_CLIENT_SECRET", "env-secret")
    monkeypatch.setenv("ALLUS_KEY_PASSPHRASE", "env-passphrase")
    monkeypatch.setenv("ALLUS_API_URL", "https://api-eu.allme.fyi")
    cfg = Config.from_file(path)
    assert cfg.client_secret == "env-secret"        # overridden
    assert cfg.key_passphrase == "env-passphrase"   # overridden
    assert cfg.api_url == "https://api-eu.allme.fyi"  # overridden
    assert cfg.client_id == "svc_abc"               # from file (no env)


def test_from_env_builds_without_a_file(monkeypatch):
    monkeypatch.setenv("ALLUS_API_URL", "https://api.allme.fyi")
    monkeypatch.setenv("ALLUS_CLIENT_ID", "svc_env")
    monkeypatch.setenv("ALLUS_CLIENT_SECRET", "env-secret")
    monkeypatch.setenv("ALLUS_SERVICE_PRIVATE_KEY", "./k.pem")
    monkeypatch.setenv("ALLUS_KEY_PASSPHRASE", "env-pass")
    cfg = Config.from_env()
    assert cfg.client_id == "svc_env"
    assert cfg.client_secret == "env-secret"


def test_missing_required_field_raises_config_error(tmp_path):
    data = _full(tmp_path)
    del data["client_secret"]  # drop a required field
    with pytest.raises(ConfigError) as exc:
        Config.from_file(_write(tmp_path, data))
    assert "client_secret" in str(exc.value)


def test_missing_file_raises_config_error(tmp_path):
    with pytest.raises(ConfigError):
        Config.from_file(str(tmp_path / "does-not-exist.json"))


def test_invalid_json_raises_config_error(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ not valid json", encoding="utf-8")
    with pytest.raises(ConfigError):
        Config.from_file(str(p))


def test_invalid_format_raises_config_error(tmp_path):
    data = _full(tmp_path)
    data["format"] = "yaml"
    with pytest.raises(ConfigError):
        Config.from_file(_write(tmp_path, data))


def test_flat_webhook_secret_shortcut(tmp_path):
    data = {
        "api_url": "https://api.allme.fyi",
        "client_id": "svc_abc",
        "client_secret": "s",
        "service_private_key": "./k.pem",
        "key_passphrase": "p",
        "webhook_secret": "the-only-secret",
    }
    cfg = Config.from_file(_write(tmp_path, data))
    # No id, or an unknown id, falls back to the single-webhook secret.
    assert cfg.webhook_secret() == "the-only-secret"
    assert cfg.webhook_secret("anything") == "the-only-secret"


def test_no_key_or_secret_is_ever_a_method_argument():
    # Config-only key handling: the cryptographic surface area on
    # Config takes no key/secret/passphrase argument. The only method,
    # webhook_secret(), takes a webhook *id* — never a secret.
    import inspect

    sig = inspect.signature(Config.webhook_secret)
    params = [p for p in sig.parameters if p != "self"]
    assert params == ["webhook_id"]
