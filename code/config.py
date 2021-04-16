import json
from uuid import NAMESPACE_X500


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings['VERSION']

    MISP_VERIFYCERT = False

    NUMBER_OF_DAYS_VERDICT_IS_VALID = 7
    NAMESPACE_BASE = NAMESPACE_X500

    SOURCE_URI = '{host}/events/view/{uuid}'

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')
