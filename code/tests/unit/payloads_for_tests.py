EXPECTED_RESPONSE_OF_JWKS_ENDPOINT = {
    'keys': [
        {
            'kty': 'RSA',
            'n': 'mRkQUiQ271QKj2_LeBefn4PIfHGLWyHGO8x76e'
                 '29z4OzY7JLb6--924yT-IGOcevE3xFudFWL0LdXdAx8X-lxQ',
            'e': 'AQAB',
            'alg': 'RS256',
            'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            'use': 'sig'
        }
    ]
}

RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY = {
    'keys': [
        {
            'kty': 'RSA',
            'n': 'jwVpCJSiQNvD9izsvPii12GcvmvXT5C6Jon'
                 'CmpuSpIP85pU2ssJua4tdM1mcR4BMGEHSEdIO25jH3dqUeK7VEw',
            'e': 'AQAB',
            'alg': 'RS256',
            'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            'use': 'sig'
        }
    ]
}

PRIVATE_KEY = '''-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAmRkQUiQ271QKj2/L
eBefn4PIfHGLWyHGO8x76e29z4OzY7JLb6++924yT+IGOcevE3xFudFWL0LdXdAx
8X+lxQIDAQABAkAgbwriHAH3WdqS4KA+ZOLQLF8A3h0jxVf1uzBVMqSPnYbeWI1r
9uP/JTNi/aA1OLXjkc9NwlSyUMfev9eDSQHRAiEA2Kf9PZCeBw8AotXkQqYxdE9/
sWwjbjCatZXe4QINLG8CIQC05lkDdmgVwllOIIJQiqVKsPazI/pq5WfgGdCZ98WT
CwIhAMriTUAovANKJkNWXwGW1frgM2i3Jlqag1YGOYelvyZbAiA4zmz9bV1aF+G7
avIBIMivH8sYjh/BGbD46qJa9zeP6QIgGlUK1ITGubEVQgatyYW83bIBo3KKgglB
2KjYzPm0Bnk=
-----END PRIVATE KEY-----'''
