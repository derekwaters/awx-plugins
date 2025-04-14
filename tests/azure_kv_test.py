"""Tests Azure Key Vault credential plugin."""

import pytest

from azure.keyvault.secrets import (
    KeyVaultSecret,
    SecretClient,
    SecretProperties,
)

from awx_plugins.credentials import azure_kv


class _FakeSecretClient(SecretClient):
    def get_secret(
        self: '_FakeSecretClient',
        name: str,
        version: str | None = None,
        **kwargs: str,
    ) -> KeyVaultSecret:
        props = SecretProperties()
        return KeyVaultSecret(properties=props, value='test-secret')


def test_azure_kv_invalid_env() -> None:
    """Test running outside of Azure raises error."""
    error_msg = (
        'You are not operating on an Azure VM, so the Managed Identity '
        'feature is unavailable. Please provide the full Client ID, '
        'Client Secret, and Tenant ID or run the software on an Azure VM.'
    )

    with pytest.raises(
        RuntimeError,
        match=error_msg,
    ):
        azure_kv.azure_keyvault_backend(
            url='https://test.vault.azure.net',
            client='',
            secret='client-secret',
            tenant='tenant-id',
            secret_field='secret',
            secret_version='',
        )


@pytest.mark.parametrize(
    ('client', 'secret', 'tenant'),
    (
        pytest.param('', '', '', id='managed-identity'),
        pytest.param(
            'client-id',
            'client-secret',
            'tenant-id',
            id='client-secret-credential',
        ),
    ),
)
def test_azure_kv_valid_auth(
    monkeypatch: pytest.MonkeyPatch,
    client: str,
    secret: str,
    tenant: str,
) -> None:
    """Test successful Azure authentication via Managed Identity and credentials."""
    monkeypatch.setattr(
        azure_kv,
        'SecretClient',
        _FakeSecretClient,
    )

    keyvault_secret = azure_kv.azure_keyvault_backend(
        url='https://test.vault.azure.net',
        client=client,
        secret=secret,
        tenant=tenant,
        secret_field='secret',
        secret_version='',
    )
    assert keyvault_secret == 'test-secret'
