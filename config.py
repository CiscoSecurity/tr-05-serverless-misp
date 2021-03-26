import os

from __version__ import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = '<API_KEY>'

    API_URL = '<API_URL'

    CCT_OBSERVABLE_TYPES = {
        'url': {'sep': '://'},
        'ip': {},
        'sha256': {},
        'domain': {}
    }
    DISPOSITIONS = {
        'clean': (1, 'Clean'),
        'malicious': (2, 'Malicious'),
        'suspicious': (3, 'Suspicious'),
        'common': (4, 'Common'),
        'unknown': (5, 'Unknown')
    }
