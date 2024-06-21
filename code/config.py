import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings['VERSION']

    MISP_VERIFYCERT = True
    MISP_TIMEOUT_SEC = 25

    SOURCE_URI = '{host}/events/view/{uuid}'

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    CTR_DEFAULT_ENTITIES_LIMIT = 100

    SUPPORTED_TYPES = {
        'ip': 'IP',
        'domain': 'domain',
        'url': 'URL',
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'md5': 'MD5',
        'hostname': 'hostname'
    }

    MEMBER_OF_RELATION = 'member-of'

    ELEMENT_OF_RELATION = 'element-of'

    MISP_REFER_URL = '{host}/events/index/searchall:{observable}'
