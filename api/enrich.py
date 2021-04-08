from functools import partial
import requests
from flask import Blueprint, current_app, g
from datetime import datetime, timedelta
from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data, format_docs
from uuid import uuid4
enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


def group_observables(relay_input):
    result = []
    for observable in relay_input:
        o_value = observable['value']
        o_type = observable['type'].lower()
        if o_type in current_app.config['CCT_OBSERVABLE_TYPES']:
            obj = {'type': o_type, 'value': o_value}
            if obj in result:
                continue
            result.append(obj)
    return result


def call_api(value, apikey):
    headers = {
        'Key': apikey
    }
    response = requests.get('https://emailrep.io/' + value, headers=headers)
    return response.json()


def get_suspicious(response):
    if (response['suspicious'] is True
            or response['details']['malicious_activity'] is True
            or response['details']['spam'] is True
            or response['details']['suspicious_tld'] is True
            or response['details']['domain_reputation'] == 'low'):
        return True
    else:
        return False


def get_disposition(response):
    if (response['details']['malicious_activity_recent'] is True
            or response['details']['blacklisted'] is True):
        return current_app.config['DISPOSITIONS']['malicious']
    elif get_suspicious(response):
        return current_app.config['DISPOSITIONS']['suspicious']
    elif response['reputation'] == 'high':
        return current_app.config['DISPOSITIONS']['clean']
    print('common')
    return current_app.config['DISPOSITIONS']['common']


def get_verdict(observable_value, observable_type, disposition, valid_time):
    if disposition[0] == 1:
        disposition_name = 'Clean'
    elif disposition[0] == 2:
        disposition_name = 'Malicious'
    elif disposition[0] == 3:
        disposition_name = 'Suspicious'
    elif disposition[0] == 4:
        disposition_name = 'Common'
    return {
        'type': 'verdict',
        'observable': {'type': observable_type, 'value': observable_value},
        'disposition': disposition[0],
        'disposition_name': disposition_name,
        'valid_time': valid_time
    }


def get_judgement(observable_value, observable_type, disposition_tuple,
                  valid_time):
    uid = 'transient:judgement-'+str(uuid4())
    sever = 'Unknown'
    if disposition_tuple[0] == 1:
        disposition_name = 'Clean'
        sever = 'Low'
    elif disposition_tuple[0] == 2:
        disposition_name = 'Malicious'
        sever = 'High'
    elif disposition_tuple[0] == 3:
        disposition_name = 'Suspicious'
        sever = 'Medium'
    elif disposition_tuple[0] == 4:
        disposition_name = 'Common'
        sever = 'Unknown'
    return {
        'type': 'judgement',
        'disposition': disposition_tuple[0],
        'observable': {'type': observable_type, 'value': observable_value},
        'disposition_name': disposition_name,
        'valid_time': valid_time,
        'priority': 90,
        'schema_version': '1.1.3',
        'confidence': 'High',
        'severity': sever,
        'source': 'Email Rep api',
        'id': uid
    }


def get_sightings(observable_value, observable_type, response):
    uid = 'transient:sighting-'+str(uuid4)
    if(response['details']['first_seen'] == 'never'
       or response['details']['last_seen'] == 'never'):
        return {}
    start = response['details']['first_seen'].split('/')
    start_time = start[-1]+start[1]+start[0]+'T00:00:00.000Z'
    end = response['details']['last_seen'].split('/')
    end_time = end[-1]+end[1]+end[0]+'T00:00:00.000Z'
    return {
        'type': 'sighting',
        'observables': [{'type': observable_type, 'value': observable_value}],
        'relations': [],
        'schema_version': '1.1.3',
        'observed_time': {'start_time': start_time, 'end_time': end_time},
        'source': 'Email Rep API',
        'source_uri': 'https://emailrep.io/'+response['email'],
        'count': 1,
        'confidence': 'High',
        'id': uid,
        'timestamp': end_time
    }


def get_indicators(observable_value, observable_type, response, valid_time):
    uid = 'transient:indicator-'+str(uuid4())
    return {
        'id': uid,
        'producer': response['email'],
        'schema_version': '1.1.3',
        'type': 'indicator',
        'valid_time': valid_time,
        'confidence': 'High',
        'source': 'Email Rep API',
        'source_uri': 'https://emailrep.io/'+response['email']
    }


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    apikey = get_jwt()
    data = {}
    g.verdicts = []
    g.judgements = []
    g.sightings = []
    g.indicators = []
    relay_input = get_json(ObservableSchema(many=True))
    observables = group_observables(relay_input)
    if not observables:
        return jsonify_data({})
    for observable in observables:
        o_type = observable['type'].lower()
        o_value = observable['value']
        response = call_api(o_value, apikey)
        disposition_tuple = get_disposition(response)
        if not disposition_tuple:
            continue
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(weeks=1)
        valid_time = {
            'start_time': start_time.isoformat() + 'Z',
            'end_time': end_time.isoformat() + 'Z',
        }
        g.verdicts.append(get_verdict(o_value, o_type, disposition_tuple,
                                      valid_time))
        g.judgements.append(get_judgement(o_value, o_type, disposition_tuple,
                            valid_time))
        sight = get_sightings(o_value, o_type, response)
        if len(sight) != 0:
            g.sightings.append(sight)
        indicate = get_indicators(o_value, o_type, response, valid_time)
        g.indicators.append(indicate)
        if g.verdicts:
            data['verdicts'] = format_docs(g.verdicts)
        if g.judgements:
            data['judgements'] = format_docs(g.judgements)
        if g.sightings:
            data['sightings'] = format_docs(g.sightings)
        if g.indicators:
            data['indicators'] = format_docs(g.indicators)
    return jsonify_data(data)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data([])
