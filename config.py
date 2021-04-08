import os

from __version__ import VERSION


class Config:
    VERSION = VERSION
    SECRET_KEY= os.environ.get('SECRET_KEY', None)
    API_URL= os.environ.get('API_URL', None)
    
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
