from flask import current_app

from api.utils import transient_id
from datetime import datetime, timedelta

CTIM_DEFAULTS = {
    'schema_version': '1.1.5'
}

SOURCE = 'MISP'

VERDICT = 'verdict'
JUDGEMENT = 'judgement'
SIGHTING = 'sighting'
INDICATOR = 'indicator'
RELATIONSHIP = 'relationship'

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

SIGHTING_DEFAULTS = {
    **CTIM_DEFAULTS,
    'type': SIGHTING,
    'count': 1,
    'confidence': 'High',
    'source': SOURCE
}

INDICATOR_DEFAULTS = {
    **CTIM_DEFAULTS,
    'type': INDICATOR,
    'confidence': 'High',
    'source': SOURCE
}

RELATIONSHIP_DEFAULTS = {
    **CTIM_DEFAULTS,
    'type': RELATIONSHIP
}

FILE_HASH_TYPES = ('md5', 'sha1', 'sha256')

THREAT_LEVEL_MAPPING = {
    1: {'disposition': 2, 'disposition_name': 'Malicious'},
    2: {'disposition': 3, 'disposition_name': 'Suspicious'},
    3: {'disposition': 4, 'disposition_name': 'Common'},
    4: {'disposition': 5, 'disposition_name': 'Unknown'}
}

ENTITY_RELEVANCE_PERIOD = timedelta(weeks=1)


class Mapping:

    def __init__(self, observable):
        self.observable = observable
        self.host = current_app.config['HOST']

    @staticmethod
    def time_format(time):
        return f'{time.isoformat(timespec="seconds")}Z'

    def _valid_time(self):
        start_time = datetime.now()
        if self.observable['type'] in FILE_HASH_TYPES:
            end_time = datetime(2525, 1, 1)
        else:
            end_time = start_time + ENTITY_RELEVANCE_PERIOD

        return {
            'start_time': self.time_format(start_time),
            'end_time': self.time_format(end_time)
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

    def _description(self, event):
        for attribute in event['Attribute']:
            if self.observable['value'] in attribute['value']:
                return f"Category: {attribute['category']}"

    def _observed_time(self, event):
        date_str = datetime.strptime(event['date'], '%Y-%m-%d')
        date = self.time_format(date_str)
        return {'start_time': date, 'end_time': date}

    def _timestamp(self, event):
        unix_timestamp = int(event['timestamp'])
        return self.time_format(datetime.utcfromtimestamp(unix_timestamp))

    def extract_sighting(self, event):
        return {
            'observables': [self.observable],
            'description': self._description(event),
            'observed_time': self._observed_time(event),
            'id': transient_id(SIGHTING),
            'source_uri': self._source_uri(event),
            'timestamp': self._timestamp(event),
            **SIGHTING_DEFAULTS
        }

    def extract_indicator(self, event):
        return {
            'short_description': self._description(event),
            'valid_time': self._observed_time(event),
            'id': transient_id(INDICATOR, event['uuid']),
            'source_uri': self._source_uri(event),
            'timestamp': self._timestamp(event),
            'tags': [tag['name'] for tag in event.get('Tag', [])],
            'producer': event['Orgc']['name'],
            'title': event['info'],
            **INDICATOR_DEFAULTS
        }

    @staticmethod
    def extract_relationship(source_ref, target_ref, relationship_type):
        return {
            'id': transient_id(RELATIONSHIP),
            'source_ref': source_ref,
            'relationship_type': relationship_type,
            'target_ref': target_ref,
            **RELATIONSHIP_DEFAULTS
        }
