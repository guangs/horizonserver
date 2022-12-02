import requests
import json
import urllib3
import logging
import sys

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)-15s| %(threadName)-18s| %(message)s", stream=sys.stdout)


class HorizonServer:
    """
    REST API Client for Horizon Connection Server
    """

    def __init__(self, username, password, domain, address):
        self._username = username
        self._password = password
        self._domain = domain
        self.address = address
        self._access_token, self._refresh_token = self._login()
        self._default_headers = {'Authorization': 'Bearer {}'.format(self._access_token),
                                 'Content-Type': 'application/json',
                                 'Accept': '*/*'}

    def http_post(self, url, data=None, json=None, headers=None, verify=False, timeout=None,
                  **kwargs) -> requests.Response:
        if headers is None:
            headers = self._default_headers
        response = requests.post(url=url, data=data, json=json, headers=headers, verify=verify, timeout=timeout,
                                 **kwargs)
        if response.status_code != 201:
            logging.info('Post[{}]: {}'.format(response.status_code, url))
            logging.info(response.json())
        response.raise_for_status()
        return response

    def http_put(self, url, data=None, json=None, headers=None, verify=False, timeout=None,
                 **kwargs) -> requests.Response:
        if headers is None:
            headers = self._default_headers
        response = requests.put(url=url, data=data, json=json, headers=headers, verify=verify, timeout=timeout,
                                **kwargs)
        if response.status_code != 204:
            logging.info('Put[{}]: {}'.format(response.status_code, url))
            logging.info(response.json())
        response.raise_for_status()
        return response

    def http_get(self, url, params=None, headers=None, verify=False, timeout=None, **kwargs) -> requests.Response:
        if headers is None:
            headers = self._default_headers
        response = requests.get(
            url=url, params=params, headers=headers, verify=verify, timeout=timeout, **kwargs)
        if response.status_code != 200:
            logging.info('Get[{}]: {}'.format(response.status_code, url))
            logging.info(response.json())
        response.raise_for_status()
        return response

    def http_delete(self, url, params=None, headers=None, verify=False, timeout=None, **kwargs) -> requests.Response:
        if headers is None:
            headers = self._default_headers
        response = requests.delete(
            url=url, params=params, headers=headers, verify=verify, timeout=timeout, **kwargs)
        if response.status_code != 204:
            logging.info('Delete[{}]: {}'.format(response.status_code, url))
            logging.info(response.json())
        response.raise_for_status()
        return response

    def _login(self):
        login_url = f'https://{self.address}/rest/login'
        data = {"username": self._username,
                "password": self._password, "domain": self._domain}
        response = requests.post(url=login_url, json=data, verify=False)
        data = response.json()
        refresh_token = data['refresh_token']
        access_token = data['access_token']
        return access_token, refresh_token

    def _logout(self):
        logout_url = f'https://{self.address}/rest/logout'
        data = {"refresh_token": self._refresh_token}
        requests.post(url=logout_url, json=data, verify=False)

    def _refresh(self):
        refresh_url = f'https://{self.address}/rest/refresh'
        data = {"refresh_token": self._refresh_token}
        response = requests.post(url=refresh_url, json=data, verify=False)
        data = response.json()
        self._access_token = data['access_token']

    @property
    def gssapi_authenticators(self):
        """
        :return: an iterable list, containing all the GSSAPIAuthenticator
        """
        url = f'https://{self.address}/rest/config/v1/gssapi-authenticators'
        response = self.http_get(url=url)
        json_list = response.json()
        # return _IterableList(json_list, GSSAPIAuthenticator, self)
        return [GSSAPIAuthenticator(item['id'], self) for item in json_list]

    def create_gssapi_authenticator(self, allow_legacy_clients=False,
                                    allow_ntlm_fallback=False,
                                    connection_server_ids=None,
                                    enable_login_as_current_user=False,
                                    enforce_channel_bindings=False,
                                    trigger_mode='DISABLED'):
        """
        :param allow_legacy_clients: True or False
        :param allow_ntlm_fallback: True or False
        :param connection_server_ids: list of connection server ids
        :param enable_login_as_current_user: True or False
        :param enforce_channel_bindings: True or False
        :param trigger_mode: "ENABLED" or "DISABLED"
        :return: new instance of GSSAPIAuthenticator
        """
        url = f'https://{self.address}/rest/config/v1/gssapi-authenticators'
        data = dict()
        data['allow_legacy_clients'] = allow_legacy_clients
        data['allow_ntlm_fallback'] = allow_ntlm_fallback
        data['connection_server_ids'] = [
        ] if not connection_server_ids else connection_server_ids
        data['enable_login_as_current_user'] = enable_login_as_current_user
        data['enforce_channel_bindings'] = enforce_channel_bindings
        data['trigger_mode'] = trigger_mode
        response = self.http_post(url=url, json=data)
        new_gssapi_authenticator_id = response.headers['Location'].split(
            '/')[-1]
        return GSSAPIAuthenticator(new_gssapi_authenticator_id, self)

    def delete_gssapi_authenticator(self, gssapi_authenticator_id):
        url = 'https://{}/rest/config/v1/gssapi-authenticators/{}'.format(
            self.address, gssapi_authenticator_id)
        self.http_delete(url=url, params={'forced': 'true'})

    @property
    def connection_servers(self):
        """
        :return: an iterable list, containing all the ConnectionServer
        """
        url = f'https://{self.address}/rest/config/v1/connection-servers'
        response = self.http_get(url=url)
        json_list = response.json()
        # return _IterableList(json_list, ConnectionServer, self)
        return [ConnectionServer(item['id'], self) for item in json_list]


class GSSAPIAuthenticator:

    def __init__(self, gssapi_authenticator_id, horizon_server: HorizonServer):
        self.id = gssapi_authenticator_id
        self.horizon_server = horizon_server
        self.url = 'https://{}/rest/config/v1/gssapi-authenticators/{}'.format(
            horizon_server.address, self.id)
        self._generate_get_response_data()
        self._generate_put_request_data()

    def __str__(self):
        return json.dumps(self.json_get_data)

    def _generate_get_response_data(self):
        response = self.horizon_server.http_get(self.url)
        self.json_get_data = response.json()

    def _generate_put_request_data(self):
        data = dict()
        data['allow_legacy_clients'] = self.allow_legacy_clients
        data['allow_ntlm_fallback'] = self.allow_ntlm_fallback
        data['enable_login_as_current_user'] = self.enable_login_as_current_user
        data['enforce_channel_bindings'] = self.enforce_channel_bindings
        data['trigger_mode'] = self.trigger_mode
        self.json_put_data = data

    @property
    def enable_login_as_current_user(self):
        return self.json_get_data['enable_login_as_current_user']

    @enable_login_as_current_user.setter
    def enable_login_as_current_user(self, enabled=True):
        self.json_put_data['enable_login_as_current_user'] = enabled
        response = self.horizon_server.http_put(
            self.url, json=self.json_put_data)
        if response.status_code == 204:
            # sync data change
            self.json_get_data['enable_login_as_current_user'] = enabled
        self._generate_get_response_data()

    @property
    def allow_legacy_clients(self):
        return self.json_get_data['allow_legacy_clients']

    @allow_legacy_clients.setter
    def allow_legacy_clients(self, enabled=True):
        self.json_put_data['allow_legacy_clients'] = enabled
        response = self.horizon_server.http_put(
            self.url, json=self.json_put_data)
        if response.status_code == 204:
            # sync data change
            self.json_get_data['allow_legacy_clients'] = enabled
        self._generate_get_response_data()

    @property
    def enforce_channel_bindings(self):
        return self.json_get_data['enforce_channel_bindings']

    @property
    def trigger_mode(self):
        return self.json_get_data['trigger_mode']

    @property
    def connection_servers(self):
        return self.json_get_data['connection_servers']

    @property
    def allow_ntlm_fallback(self):
        return self.json_get_data['allow_ntlm_fallback']


class ConnectionServer:

    def __init__(self, connection_server_id, horizon_server: HorizonServer):
        self.id = connection_server_id
        self.horizon_server = horizon_server
        self.url = 'https://{}/rest/config/v1/connection-servers/{}'.format(
            horizon_server.address, self.id)
        self._generate_get_response_data()

    def __str__(self):
        return json.dumps(self.json_get_data)

    def _generate_get_response_data(self):
        response = self.horizon_server.http_get(self.url)
        self.json_get_data = response.json()
