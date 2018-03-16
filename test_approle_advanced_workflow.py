import unittest
import os
import hvac
from hvac import exceptions

APP_NAME = 'fooApp'
CONFIDENTIAL = 'aslkf093240-89890234rasf'


class AppRoleAdvanceWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.vault_addr = os.getenv('VAULT_ADDR', 'http://192.168.3.192:8201')
        self.vault_admin_token = os.getenv('VAULT_ADMIN_TOKEN', '522b2394-0264-93c0-3683-6b1624eeab02')

        self.vault_admin = VaultAdmin(self.vault_addr, self.vault_admin_token)
        self.jenkins = Jenkins(self.vault_addr, self.vault_admin_token)

        self.vault_admin.setup_app(APP_NAME)
        self.jenkins.write_app_secret(APP_NAME, CONFIDENTIAL)
        role_id, wrapping_token = self.jenkins.get_role(APP_NAME)
        self.jenkins.delivery_app(self.vault_addr, role_id, wrapping_token)

    def tearDown(self):
        pass

    def test_app_get_secret(self):
        foo_app = FooApp()
        foo_app.get_secret_id()
        foo_app.login_vault()
        confidential = foo_app.read_secret()
        self.assertEqual(CONFIDENTIAL, confidential)

    def test_token_one_time_used(self):
        foo_app = FooApp()
        foo_app.get_secret_id()
        foo_app.login_vault()
        foo_app.read_secret()
        with self.assertRaises(exceptions.Forbidden):
            foo_app.read_secret()

    def test_revoke_role(self):
        self.vault_admin.revoke(APP_NAME)
        with self.assertRaises(exceptions.InternalServerError):
            foo_app = FooApp()
            foo_app.get_secret_id()
            foo_app.login_vault()

    def test_wrapping_token_single_use(self):
        foo_app = FooApp()
        foo_app.get_secret_id()
        with self.assertRaises(exceptions.Forbidden):
            foo_app.get_secret_id()

    def test_wrapping_token_ttl(self):
        import time
        time.sleep(1)
        foo_app = FooApp()
        with self.assertRaises(exceptions.Forbidden):
            foo_app.get_secret_id()


class FooApp:
    def __init__(self):
        self.vault_addr = os.getenv('VAULT_ADDR')
        self.role_id = os.getenv('ROLE_ID')
        self.secret_id = None
        self.wrapping_token = os.getenv('WRAPPING_TOKEN')

    def get_secret_id(self):
        client = hvac.Client(url=self.vault_addr)
        resp = client.unwrap(self.wrapping_token)
        self.secret_id = resp['data']['secret_id']

    def login_vault(self):
        client = hvac.Client(url=self.vault_addr)
        resp = client.write('auth/approle/login', role_id=self.role_id, secret_id=self.secret_id)
        self.vault_token = resp['auth']['client_token']

    def read_secret(self):
        client = hvac.Client(url=self.vault_addr, token=self.vault_token)
        resp = client.read('secret/%s' % APP_NAME)
        return resp['data']['value']


class VaultAdmin:
    def __init__(self, vault_addr, vault_token):
        self.vault_addr = vault_addr
        self.vault_token = vault_token
        self.vault_client = hvac.Client(url=self.vault_addr, token=self.vault_token)

    def setup_app(self, app_name):
        policy = """
        path "auth/approle/login" {
            capabilities = ["read", "create"]
        }
        
        path "secret/%s" {
            capabilities = ["read"]
        }
        """ % app_name
        policy_name = '%s_role_policy' % app_name

        self.vault_client.set_policy(policy_name, policy)
        self.vault_client.write('auth/approle/role/%s' % app_name, policies=policy_name, token_num_uses=1)

    def revoke(self, app_name):
        self.vault_client.delete('auth/approle/role/%s' % app_name)


class Jenkins:
    def __init__(self, vault_addr, vault_token):
        self.vault_addr = vault_addr
        self.vault_token = vault_token
        self.vault_client = hvac.Client(url=self.vault_addr, token=self.vault_token)

    def get_role(self, app_name):
        resp = self.vault_client.read('auth/approle/role/%s/role-id' % app_name)
        role_id = resp['data']['role_id']
        resp = self.vault_client.write('auth/approle/role/%s/secret-id' % app_name, wrap_ttl=1)
        wrapping_token = resp['wrap_info']['token']

        return role_id, wrapping_token

    def write_app_secret(self, app_name, confidential):
        self.vault_client.write("secret/%s" % app_name, value=confidential)

    def delivery_app(self, vault_addr, role_id, wrapping_token):
        os.environ['VAULT_ADDR'] = vault_addr
        os.environ['ROLE_ID'] = role_id
        os.environ['WRAPPING_TOKEN'] = wrapping_token
