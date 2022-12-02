from horizonserver import HorizonServer


def test_enable_login_as_current_user(enabled=True):
    username = r'administrator'
    password = r'ca$hc0w'
    domain = r'wbd'
    address = '10.117.30.135'
    hs = HorizonServer(username=username, password=password,
                       domain=domain, address=address)
    if not hs.gssapi_authenticators:
        hs.create_gssapi_authenticator(
            False, False, [cs.id for cs in hs.connection_servers], enabled, False, 'DISABLED')
    else:
        for gssapi_auth in hs.gssapi_authenticators:
            gssapi_auth.enable_login_as_current_user = enabled


if __name__ == '__main__':

    test_enable_login_as_current_user(enabled=True)
