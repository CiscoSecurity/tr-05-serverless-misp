import os

from __version__ import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = 'SIkW4edEIPBiAyDQQuixDExGcKWOwCz8hojNergQBO796B30fVilrER3aDq3yFeu'

    API_URL = 'https://100.27.2.155/'

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
