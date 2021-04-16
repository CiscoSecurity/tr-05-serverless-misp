from flask import current_app

from api.utils import transient_id
from datetime import datetime, timedelta

CTIM_DEFAULTS = {
    'schema_version': '1.1.5',
}

SOURCE = 'MISP'

VERDICT = 'verdict'
JUDGEMENT = 'judgement'

VERDICT_DEFAULTS = {
    'type': VERDICT
}

JUDGEMENT_DEFAULTS = {
    **CTIM_DEFAULTS,
    'type': JUDGEMENT,
    'source': SOURCE,
    'priority': 85,
    'confidence': 'Medium',
    'severity': 'Medium'
}

FILE_HASH_TYPES = ('md5', 'sha1', 'sha256')

THREAT_LEVEL_MAPPING = {
    1: {'disposition': 2, 'disposition_name': 'Malicious'},
    2: {'disposition': 3, 'disposition_name': 'Suspicious'},
    3: {'disposition': 4, 'disposition_name': 'Common'},
    4: {'disposition': 5, 'disposition_name': 'Unknown'}
}

ENTITY_RELEVANCE_PERIOD = timedelta(weeks=1)


def time_format(time):
    return f'{time.isoformat(timespec="seconds")}Z'


class Mapping:

    def __init__(self, observable):
        self.observable = observable
        self.host = current_app.config['HOST']

    def _valid_time(self):
        start_time = datetime.now()
        if self.observable['type'] in FILE_HASH_TYPES:
            end_time = datetime(2525, 1, 1)
        else:
            end_time = start_time + ENTITY_RELEVANCE_PERIOD

        return {
            'start_time': time_format(start_time),
            'end_time': time_format(end_time)
        }

    def _source_uri(self, event):
        return current_app.config['SOURCE_URI'].format(
            host=self.host, uuid=event['uuid']
        )

    @staticmethod
    def _disposition(event):
        score = event['threat_level_id']
        return THREAT_LEVEL_MAPPING[int(score)]

    def extract_verdict(self, event):
        return {
            **self._disposition(event),
            'observable': self.observable,
            'valid_time': self._valid_time(),
            **VERDICT_DEFAULTS
        }

    def extract_judgement(self, event):
        return {
            **self._disposition(event),
            'observable': self.observable,
            'valid_time': self._valid_time(),
            'id': transient_id(JUDGEMENT),
            'source_uri': self._source_uri(event),
            **JUDGEMENT_DEFAULTS
        }
