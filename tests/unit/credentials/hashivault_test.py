import pytest
from pytest_mock import MockerFixture

from awx_plugins.credentials import hashivault


def test_hashivault_approle_auth() -> None:
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
    kwargs: dict[str, str] = {}
    expected_res = {
        'name': None,
    }
    res = hashivault.client_cert_auth(  # type: ignore[no-untyped-call]
        **kwargs,
    )
    assert res == expected_res


def test_hashivault_userpass_auth() -> None:
    kwargs = {'username': 'the_username', 'password': 'the_password'}
    expected_res = {'username': 'the_username', 'password': 'the_password'}
    res = hashivault.userpass_auth(**kwargs)  # type: ignore[no-untyped-call]
    assert res == expected_res


def test_hashivault_handle_auth_token() -> None:
    kwargs = {
        'token': 'the_token',
    }
    token = hashivault.handle_auth(**kwargs)  # type: ignore[no-untyped-call]
    assert token == kwargs['token']


def test_hashivault_handle_auth_approle(mocker: MockerFixture) -> None:
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
    with pytest.raises(Exception):
        hashivault.handle_auth()  # type: ignore[no-untyped-call]
