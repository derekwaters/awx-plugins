"""Tests for HashiCorp Vault credential plugins."""

import pytest
from pytest_mock import MockerFixture

from awx_plugins.credentials import hashivault
from awx_plugins.credentials.plugin import CredentialPlugin


def test_hashivault_approle_auth() -> None:
    """Test ``approle_auth()`` method returns known secret."""
    kwargs = {
        'role_id': 'the_role_id',
        'secret_id': 'the_secret_id',
    }
    expected_res = {
        'role_id': 'the_role_id',
        'secret_id': 'the_secret_id',
    }
    res = hashivault.approle_auth(**kwargs)  # type: ignore[no-untyped-call]
    assert res == expected_res


def test_hashivault_kubernetes_auth(mocker: MockerFixture) -> None:
    """Test ``kubernetes_auth()`` method returns known JWT."""
    kwargs = {
        'kubernetes_role': 'the_kubernetes_role',
    }
    expected_res = {
        'role': 'the_kubernetes_role',
        'jwt': 'the_jwt',
    }
    path_mock = mocker.patch('pathlib.Path')
    path_mock.return_value.open = mocker.mock_open(read_data='the_jwt')
    res = hashivault.kubernetes_auth(  # type: ignore[no-untyped-call]
        **kwargs,
    )
    path_mock.assert_called_with(
        '/var/run/secrets/kubernetes.io/serviceaccount/token',
    )
    assert res == expected_res


def test_hashivault_client_cert_auth_explicit_role() -> None:  # noqa: WPS118
    """Test ``client_cert_auth()`` with explicit role returns a certificate."""
    kwargs = {
        'client_cert_role': 'test-cert-1',
    }
    expected_res = {
        'name': 'test-cert-1',
    }
    res = hashivault.client_cert_auth(  # type: ignore[no-untyped-call]
        **kwargs,
    )
    assert res == expected_res


def test_hashivault_client_cert_auth_no_role() -> None:
    """Test ``client_cert_auth()`` with no role returns no name."""
    kwargs: dict[str, str] = {}
    expected_res = {
        'name': None,
    }
    res = hashivault.client_cert_auth(  # type: ignore[no-untyped-call]
        **kwargs,
    )
    assert res == expected_res


def test_hashivault_userpass_auth() -> None:
    """Test ``userpass_auth()`` returns the password."""
    kwargs = {'username': 'the_username', 'password': 'the_password'}
    expected_res = {'username': 'the_username', 'password': 'the_password'}
    res = hashivault.userpass_auth(**kwargs)  # type: ignore[no-untyped-call]
    assert res == expected_res


def test_hashivault_handle_auth_token() -> None:
    """Test ``handle_auth()`` with token auth returns the token."""
    kwargs = {
        'token': 'the_token',
    }
    token = hashivault.handle_auth(**kwargs)  # type: ignore[no-untyped-call]
    assert token == kwargs['token']


def test_hashivault_handle_auth_approle(mocker: MockerFixture) -> None:
    """Test ``handle_auth()`` with approle auth returns the token."""
    kwargs = {
        'role_id': 'the_role_id',
        'secret_id': 'the_secret_id',
    }
    method_mock = mocker.patch.object(hashivault, 'method_auth')
    method_mock.return_value = 'the_token'
    token = hashivault.handle_auth(  # type: ignore[no-untyped-call]
        **kwargs,
    )
    method_mock.assert_called_with(**kwargs, auth_param=kwargs)
    assert token == 'the_token'


def test_hashivault_handle_auth_kubernetes(mocker: MockerFixture) -> None:
    """Test ``handle_auth()`` with k8s role and JWT auth returns a token."""
    kwargs = {
        'kubernetes_role': 'the_kubernetes_role',
    }
    method_mock = mocker.patch.object(hashivault, 'method_auth')
    path_mock = mocker.patch('pathlib.Path')
    path_mock.return_value.open = mocker.mock_open(read_data='the_jwt')
    method_mock.return_value = 'the_token'
    token = hashivault.handle_auth(  # type: ignore[no-untyped-call]
        **kwargs,
    )
    method_mock.assert_called_with(
        **kwargs,
        auth_param={
            'role': 'the_kubernetes_role',
            'jwt': 'the_jwt',
        },
    )
    assert token == 'the_token'


def test_hashivault_handle_auth_client_cert(mocker: MockerFixture) -> None:
    """Test ``handle_auth()`` with client certificate auth returns a token."""
    kwargs = {
        'client_cert_public': 'foo',
        'client_cert_private': 'bar',
        'client_cert_role': 'test-cert-1',
    }
    auth_params = {
        'name': 'test-cert-1',
    }
    method_mock = mocker.patch.object(hashivault, 'method_auth')
    method_mock.return_value = 'the_token'
    token = hashivault.handle_auth(  # type: ignore[no-untyped-call]
        **kwargs,
    )
    method_mock.assert_called_with(**kwargs, auth_param=auth_params)
    assert token == 'the_token'


def test_hashivault_handle_auth_not_enough_args() -> None:
    """Test ``handle_auth()`` errors out on inssuficient arguments."""
    expected_error_msg = (
        r'^Token, Username/Password, AppRole, Kubernetes, or TLS '
        r'authentication parameters must be set$'
    )
    with pytest.raises(Exception, match=expected_error_msg):
        hashivault.handle_auth()  # type: ignore[no-untyped-call]


@pytest.mark.parametrize(
    ('plugin', 'field_type', 'expected_ids'),
    (
        pytest.param(
            hashivault.hashivault_kv_plugin,
            'fields',
            [
                'url',
                'token',
                'cacert',
                'role_id',
                'secret_id',
                'client_cert_public',
                'client_cert_private',
                'client_cert_role',
                'namespace',
                'kubernetes_role',
                'username',
                'password',
                'default_auth_path',
                'api_version',
            ],
            id='kv-fields',
        ),
        pytest.param(
            hashivault.hashivault_kv_plugin,
            'metadata',
            [
                'secret_backend',
                'secret_path',
                'auth_path',
                'secret_key',
                'secret_version',
            ],
            id='kv-metadata',
        ),
        pytest.param(
            hashivault.hashivault_ssh_plugin,
            'fields',
            [
                'url',
                'token',
                'cacert',
                'role_id',
                'secret_id',
                'client_cert_public',
                'client_cert_private',
                'client_cert_role',
                'namespace',
                'kubernetes_role',
                'username',
                'password',
                'default_auth_path',
            ],
            id='ssh-fields',
        ),
        pytest.param(
            hashivault.hashivault_ssh_plugin,
            'metadata',
            [
                'public_key',
                'secret_path',
                'auth_path',
                'role',
                'valid_principals',
            ],
            id='ssh-metadata',
        ),
    ),
)
def test_plugin_input_ids(
    plugin: CredentialPlugin,
    field_type: str,
    expected_ids: list[str],
) -> None:
    """Verify plugin input fields/metadata are present with expected IDs."""
    plugin_inputs = plugin.inputs
    actual_ids = [
        plugin['id']
        # NOTE: `CredentialPlugin` aren't yet fully typed:
        for plugin in plugin_inputs[field_type]  # type: ignore[index]
    ]
    assert actual_ids == expected_ids
