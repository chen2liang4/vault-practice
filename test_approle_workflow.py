import unittest
import os
import hvac
from hvac import exceptions

CONFIDENTIAL = 'aslkf09324089890234rasf'


class AppRoleTokenProviderTest(unittest.TestCase):
    def setUp(self):
        self.app_name = 'x-app'
        self.app_secret = 'secret/%s' % self.app_name
        self.vault_addr = 'http://192.168.3.192:8201'
        self.vault_admin_token = '522b2394-0264-93c0-3683-6b1624eeab02'

        vault_admin = VaultAdmin(self.vault_addr, self.vault_admin_token)
        role_id, role_token = vault_admin.setup_app(self.app_name)
        vault_admin.write_app_secret(self.app_name, CONFIDENTIAL)

        deploy_process = DeploymentProcess()
        deploy_process.deploy_app(self.vault_addr, role_id, role_token, self.app_name)

    def tearDown(self):
        pass

    def test_app_get_secret(self):
        token_provider = TokenProvider()
        token = token_provider.request_token()

        client = hvac.Client(self.vault_addr, token=token)
        resp = client.read(self.app_secret)
        self.assertEqual(CONFIDENTIAL, resp['data']['value'])

    def test_token_single_used(self):
        token = TokenProvider().request_token()

        client = hvac.Client(self.vault_addr, token=token)
        client.read(self.app_secret)
        with self.assertRaises(exceptions.Forbidden):
            client.read(self.app_secret)

    def test_token_release(self):
        token = TokenProvider().request_token()

        client = hvac.Client(self.vault_addr, token=token)
        admin_client = hvac.Client(self.vault_addr, self.vault_admin_token)

        admin_client.lookup_token(token=token)
        client.read(self.app_secret)
        with self.assertRaises(exceptions.Forbidden):
            admin_client.lookup_token(token=token)

    def test_revoke_role(self):
        admin_client = VaultAdmin(self.vault_addr, self.vault_admin_token)
        old_role_id = os.getenv('ROLE_ID')

        admin_client.revoke(self.app_name)
        with self.assertRaises(exceptions.InvalidRequest):
            TokenProvider().request_token()

        new_role_id, new_role_token = admin_client.setup_app(self.app_name)
        DeploymentProcess().deploy_app(self.vault_addr, new_role_id, new_role_token, self.app_name)
        TokenProvider().request_token()

    def test_revoke_role_token(self):
        tokenProvider = TokenProvider()
        tokenProvider.request_token()

        admin_client = hvac.Client(self.vault_addr, self.vault_admin_token)
        role_token = os.getenv("ROLE_TOKEN")
        admin_client.revoke_token(role_token)

        with self.assertRaises(exceptions.Forbidden):
            tokenProvider.request_token()

    #
    def test_two_clients(self):
        # get the token for first client
        first_role_token = TokenProvider().request_token()

        # deploy the second client
        second_role_id, second_role_token = VaultAdmin(self.vault_addr, self.vault_admin_token).setup_app(self.app_name)
        DeploymentProcess().deploy_app(self.vault_addr, second_role_id, second_role_token, self.app_name)
        second_role_token = TokenProvider().request_token()

        self.assertNotEqual(first_role_token, second_role_token)

        first_client = hvac.Client(self.vault_addr, token=first_role_token)
        resp = first_client.read(self.app_secret)
        self.assertEqual(CONFIDENTIAL, resp['data']['value'])
        second_client = hvac.Client(self.vault_addr, token=second_role_token)
        resp = second_client.read(self.app_secret)
        self.assertEqual(CONFIDENTIAL, resp['data']['value'])


class TokenProvider:
    def __init__(self):
        # get parameters from environment
        # alternatives:
        # 1. hard code in compiling/deployment
        # 2. save to local vault file in deployment
        self.vault_addr = os.getenv('VAULT_ADDR')
        self.role_id = os.getenv('ROLE_ID')
        self.role_token = os.getenv('ROLE_TOKEN')
        self.role = os.getenv('ROLE')

    def request_token(self):
        client = hvac.Client(url=self.vault_addr, token=self.role_token)
        resp = client.write('auth/approle/role/%s/secret-id' % self.role)
        secret_id = resp['data']['secret_id']

        print('role_id: %s, secret_id: %s' % (self.role_id, secret_id))
        print(secret_id)

        resp = client.write('auth/approle/login', role_id=self.role_id, secret_id=secret_id)
        app_client_token = resp['auth']['client_token']
        os.environ['APP_TOKEN'] = app_client_token
        return app_client_token


class VaultAdmin:
    def __init__(self, vault_addr, vault_token):
        self.vault_addr = vault_addr
        self.vault_token = vault_token
        self.admin_client = hvac.Client(url=self.vault_addr, token=self.vault_token)

    def setup_app(self, app_name):
        app_secret_policy = """
        path "secret/%s" {
            capabilities = ["read"]
        }
        """ % app_name
        app_role_policy = """
        path "auth/approle/role/%s/secret-id" {
            capabilities = ["read", "create", "update"]
        }
        """ % app_name

        secret_policy_name = '%s_secret_policy' % app_name
        self.admin_client.set_policy(secret_policy_name, app_secret_policy)
        role_policy_name = '%s_role_policy' % app_name
        self.admin_client.set_policy(role_policy_name, app_role_policy)

        self.admin_client.write('auth/approle/role/%s' % app_name,
                                policies=secret_policy_name,
                                secret_id_num_uses=1,
                                token_num_uses=1)
        resp = self.admin_client.read('auth/approle/role/%s/role-id' % app_name)
        role_id = resp['data']['role_id']

        resp = self.admin_client.create_token(policies=[role_policy_name])
        role_token = resp['auth']['client_token']
        return role_id, role_token

    def write_app_secret(self, app_name, confidential):
        self.admin_client.write("secret/%s" % app_name, value=confidential)

    def revoke(self, app_name):
        self.admin_client.delete('auth/approle/role/%s' % app_name)


class DeploymentProcess:
    def __init__(self):
        pass

    def deploy_app(self, vault_addr, role_id, role_token, role):
        os.environ['VAULT_ADDR'] = vault_addr
        os.environ['ROLE_ID'] = role_id
        os.environ['ROLE_TOKEN'] = role_token
        os.environ['ROLE'] = role
