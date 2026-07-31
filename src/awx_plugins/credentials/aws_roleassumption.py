"""AWS IAM Role Assumption Lookup Credential Plugin.

This module provides the ability to retrieve AWS credentials from a short-lived
assumed STS role
"""

import datetime
import hashlib
import typing as _t

from awx_plugins.interfaces._temporary_private_django_api import (  # noqa: WPS436
    gettext_noop as _,
)

import boto3

from . import _types
from .plugin import CredentialPlugin

_aws_cred_cache: dict[str, dict[str, str] ] = {}

# Base input fields
access_key_field: _types.FieldDict = {
    'id': 'access_key',
    'label': 'AWS Access Key',
    'type': 'string',
    'help_text': _(
        'The AWS Access Key for the account assuming the named IAM role.',
    ),
}

secret_key_field: _types.FieldDict = {
    'id': 'secret_key',
    'label': 'AWS Secret Key',
    'type': 'string',
    'secret': True,
    'help_text': _(
        'The AWS Secret Key for the account assuming the named IAM role.',
    ),
}

external_id_field: _types.FieldDict = {
    'id': 'external_id',
    'label': 'External ID',
    'type': 'string',
    'help_text': _('An optional external identifier used in AWS IAM tracing'),
}

role_arn_field: _types.FieldDict = {
    'id': 'role_arn',
    'label': 'AWS ARN Role Name',
    'type': 'string',
}

# Base input metadata
identifier_metadata: _types.MetadataDict = {
    'id': 'identifier',
    'label': 'Identifier',
    'type': 'string',
    'multiline': False,
    'help_text': _(
        'The name of the key in the assumed AWS'
        ' role to fetch [AccessKeyId | SecretAccessKey | SessionToken].',
    ),
}

# Plugin Input Definition
aws_role_assumption_inputs: _types.PluginInputs = {
    'fields': [
        access_key_field,
        secret_key_field,
        external_id_field,
        role_arn_field,
    ],
    'metadata': [
        identifier_metadata,
    ],
    'required': [
        role_arn_field['id'],
    ],
}


def aws_role_assumption_backend(  # noqa: WPS211
    *,
    access_key: str,
    secret_key: str,
    role_arn: str,
    external_id: str,
    identifier: str,
    **_discarded_kwargs: _t.Unpack[_t.EmptyKwargs],
) -> str:
    """Assume the specified AWS IAM role using the supplied credentials."""
    # Generate a hash unique MD5 for combo of user access key and ARN
    # This should allow two users requesting the same ARN role to have
    # separate credentials, and should allow the same user to request
    # multiple roles.
    credential_key_hash = hashlib.md5((access_key + role_arn).encode('utf-8'))  # noqa: S324
    credential_key = credential_key_hash.hexdigest()

    credentials = _aws_cred_cache.get(credential_key)

    # If there are no credentials for this user/ARN *or* the credentials
    # we have in the cache have expired, then we need to contact AWS again.
    if (credentials is None) or (
        credentials['Expiration']
        < datetime.datetime.now(credentials['Expiration'].tzinfo)
    ):
        if (access_key is None or len(access_key) == 0) and (
            secret_key is None or len(secret_key) == 0
        ):
            # Connect using credentials in the EE
            connection = boto3.client(
                service_name='sts',
            )
        else:
            # Connect to AWS using provided credentials
            connection = boto3.client(
                service_name='sts',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )
        response = connection.assume_role(
            RoleArn=role_arn,
            RoleSessionName='AAP_AWS_Role_Session1',
            ExternalId=external_id,
        )

        credentials = response.get('Credentials', {})

        _aws_cred_cache[credential_key] = credentials

    credentials = _aws_cred_cache.get(credential_key)
    if credentials is not None:
        result_identifier = credentials.get(identifier)
        if result_identifier is not None:
            return result_identifier

    raise ValueError(f'Could not find a value for {identifier}.')


aws_role_assumption_plugin = CredentialPlugin(
    'AWS Role Assumption Lookup',
    # see: https://docs.ansible.com/ansible-tower/latest/html/userguide/credential_types.html
    # inputs will be used to create a new CredentialType() instance
    # see: https://github.com/ansible/awx-custom-credential-plugin-example
    inputs=aws_role_assumption_inputs,
    backend=aws_role_assumption_backend,
    plugin_description='Lookup AWS short-lived credentials using AWS IAM Role Assumption',
)
