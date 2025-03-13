.. _ug_credential_plugins:

Secret Management System
========================

.. index::
   single: credentials
   pair: credential; plugins
   pair: secret management; credential

Users and admins upload machine and cloud credentials so that automation can access machines and external services on their behalf. By default, sensitive credential values (such as SSH passwords, SSH private keys, API tokens for cloud services) are stored in the database after being encrypted. With external credentials backed by credential plugins, you can map credential fields (like a password or an SSH Private key) to values stored in a secret management system instead of providing them to AWX directly. AWX currently provides the ability for users to create their own credential plugins.

These external secret values will be fetched prior to running a playbook that needs them.

Configure and link secret lookups
---------------------------------

When configuring AWX to pull a secret from a 3rd-party system, it is in essence linking credential fields to external systems. To link a credential field to a value stored in an external system, select the external credential corresponding to that system and provide metadata to look up the desired value. The metadata input fields are part of the external credential type definition of the source credential.

AWX provides a credential plugin interface for developers, integrators, admins, and power-users with the ability to add new external credential types to extend it to support other secret management systems. For more detail, see the `development docs for credential plugins`_.

.. _`development docs for credential plugins`: https://github.com/ansible/awx/blob/devel/docs/credentials/credential_plugins.md


Use the AWX User Interface to configure and use each of the supported 3-party secret management systems.

1. First, create an external credential for authenticating with the secret management system. See :ref:`ug_credentials_add`. At minimum, provide a name for the external credential and select your desired secret lookup from the :guilabel:`Credential Type` drop-down menu.


2. Navigate to the credential form of the target credential and link one or more input fields to the external credential along with metadata for locating the secret in the external system. In this example, the *Demo Credential* is the target credential.

.. _ag_credential_plugins_link_step:

3. For any of the fields below the **Type Details** area that you want to link to the external credential, click the |key| button of the input field. You are prompted to set the input source to use to retrieve your secret information.

.. |key| image:: _static/images/key-mgmt-button.png
   :alt: Icon for managing external credentials

4. Select the credential you want to link to, and enter the :guilabel:`Metadata` of the input source. Metadata is specific to the input source you select.

5. Click :guilabel:`Test` to verify connection to the secret management system. If the lookup is unsuccessful, an error message with a noted exception displays.

6. When done, click :guilabel:`OK`. This closes the prompt window and returns you to the Details screen of your target credential. **Repeat these steps**, starting with :ref:`step 3 above <ag_credential_plugins_link_step>` to complete the remaining input fields for the target credential. By linking the information in this manner, AWX retrieves sensitive information, such as username, password, keys, certificates, and tokens from the 3rd-party management systems and populates that data into the remaining fields of the target credential form.

7. If necessary, supply any information manually for those fields that do not use linking as a way of retrieving sensitive information.

8. Click :guilabel:`Save` when done.
