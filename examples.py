from horizonserver import HorizonServer

def test_enable_login_as_current_user(enabled=True):
    username = r'administrator'
    password = r'ca$hc0w'
    domain = r'wbd'
    address = '10.117.30.135'
    cs = HorizonServer(username=username, password=password, domain=domain, address=address)
    if not cs.gssapi_authenticators:
        cs.create_gssapi_authenticator(False, False, cs.connection_servers.ids, enabled, False, 'DISABLED')
    else:
        for gssapi_auth in cs.gssapi_authenticators:
            gssapi_auth.enable_login_as_current_user = enabled


if __name__ == '__main__':

    test_enable_login_as_current_user(enabled=True)