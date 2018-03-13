import unittest
import os
import hvac
from hvac import exceptions

CONFIDENTIAL = 'aslkf09324089890234rasf'


class AppRoleTokenProviderTest(unittest.TestCase):
    def setUp(self):
        self.vault_addr = 'http://192.168.3.192:8201'
        vault_admin_token = '522b2394-0264-93c0-3683-6b1624eeab02'

        self.role_id, self.role_token = self.vault_admin_init(self.vault_addr, vault_admin_token)
        self.app_security_write_secret(self.vault_addr, vault_admin_token, CONFIDENTIAL)
        self.deploy_app(self.vault_addr, self.role_id, self.role_token, 'x-app')

    def tearDown(self):
        pass

    def test_app_get_secret(self):
        token_provider = TokenProvider()
        token = token_provider.request_token()

        client = hvac.Client(self.vault_addr, token=token)
        resp = client.read('secret/x-app')
        self.assertEqual(CONFIDENTIAL, resp['data']['value'])

    def test_token_single_used(self):
        token = TokenProvider().request_token()

        client = hvac.Client(self.vault_addr, token=token)
        client.read('secret/x-app')
        with self.assertRaises(exceptions.Forbidden):
            client.read('secret/x-app')

    def vault_admin_init(self, vault_addr, vault_admin_token):
        admin_client = hvac.Client(url=vault_addr, token=vault_admin_token)

        app_secret_policy = """
        path "secret/x-app" {
            capabilities = ["read"]
        }
        """
        app_role_policy = """
        path "auth/approle/role/x-app/secret-id" {
            capabilities = ["read", "create", "update"]
        }
        """
        admin_client.set_policy("app_secret_policy ", app_secret_policy)
        admin_client.set_policy("appRole_secretId_policy", app_role_policy)

        admin_client.write('auth/approle/role/x-app', policies="app_secret_policy ", token_num_uses=1)
        admin_client.write('secret/x-app', password='vault-exercise')

        resp = admin_client.read('auth/approle/role/x-app/role-id')
        role_id = resp['data']['role_id']

        resp = admin_client.create_token(policies=['appRole_secretId_policy'])
        role_token = resp['auth']['client_token']
        return role_id, role_token

    def app_security_write_secret(self, vault_addr, vault_token, confidential_information):
        security_client = hvac.Client(url=vault_addr, token=vault_token)
        security_client.write("secret/x-app", value=confidential_information)

    def deploy_app(self, vault_addr, role_id, role_token, role):
        os.environ['VAULT_ADDR'] = vault_addr
        os.environ['ROLE_ID'] = role_id
        os.environ['ROLE_TOKEN'] = role_token
        os.environ['ROLE'] = role


class TokenProvider:
    def __init__(self):
        self.vault_addr = os.getenv('VAULT_ADDR')
        self.role_id = os.getenv('ROLE_ID')
        self.role_token = os.getenv('ROLE_TOKEN')
        self.role = os.getenv('ROLE')

    def request_token(self):
        client = hvac.Client(url=self.vault_addr, token=self.role_token)
        resp = client.write('auth/approle/role/%s/secret-id' % self.role)
        secret_id = resp['data']['secret_id']

        resp = client.write('auth/approle/login', role_id=self.role_id, secret_id=secret_id)
        app_client_token = resp['auth']['client_token']
        os.environ['APP_TOKEN'] = app_client_token
        return app_client_token
