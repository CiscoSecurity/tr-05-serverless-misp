from functools import partial
import json
import requests
from flask import Blueprint, current_app, jsonify, g
from datetime import datetime, timedelta
from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data, format_docs


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


def build_input_api(observables):
    for observable in observables:
        o_value = observable['value']
        o_type = observable['type'].lower()
        if current_app.config['CCT_OBSERVABLE_TYPES'][o_type].get('sep'):
            o_value = o_value.split(
                current_app.config['CCT_OBSERVABLE_TYPES'][o_type]['sep'])[-1]
            observable['value'] = o_value
    return observables


def call_api(type, value, misp):
    headers = {
        'Accept': 'application/json',
        'Connection': 'keep-alive',
        'Authorization': misp,
        'Content-Type': 'application/json'
    }
    data = {
        'responseFormat': 'json'
    }
    observable_values = {
        'url': 'url',
        'ip': 'ip-src',
        'sha256': 'sha256',
        'domain': 'domain'
    }
    data['type'] = observable_values[type]
    data['value'] = value
    x = json.dumps(data)
    response = requests.post(current_app.config['API_URL']
                             + 'attributes/restSearch',
                             headers=headers, data=x, verify=False)
    res = response.json()
    if(len(res['response']['Attribute']) == 0):
        return ({}, {})
    event_id = res['response']['Attribute'][0]['event_id']
    result = requests.get(current_app.config['API_URL']
                          + 'events/view/' + event_id,
                          headers=headers, data={}, verify=False)
    return (result.json(), res)


def get_tlp(disposition, attribute):
    if ('Tag' in attribute['response']['Attribute'][0]):
        tag = attribute['response']['Attribute'][0]['Tag'][0]
        if('name' in tag and tag['name'][:3] == 'tlp'):
            return tag['name'][4:]
    if('Tag' in disposition['Event']):
        tag = disposition['Event']['Tag'][0]
        if('name' in tag and tag['name'][:3] == 'tlp'):
            return tag['name'][4:]
    return ''


def get_disposition(disposition):
    threat_id = disposition['Event']['threat_level_id']
    threats = {
        '1': 'malicious',
        '2': 'suspicious',
        '3': 'clean'
    }
    return current_app.config['DISPOSITIONS'][threats.get(threat_id,
                                                          'unknown')]


def get_verdict(observable_value, observable_type, disposition, valid_time):
    dis = {
        1: 'Clean',
        2: 'Malicious',
        3: 'Suspicious',
        4: 'Common',
        5: 'Unknown'
    }
    disposition_name = dis.get(disposition[0], 'Unknown')
    return {
        'type': 'verdict',
        'observable': {'type': observable_type, 'value': observable_value},
        'disposition': disposition[0],
        'disposition_name': disposition_name,
        'valid_time': valid_time
    }


def get_judgement(observable_value, observable_type, disposition, valid_time,
                  disp, attribute, tlp):
    uuid = 'transient:judgement-' + disp['Event']['uuid']
    sever = 'Unknown'
    dis = {
        1: ('Clean', 'Low'),
        2: ('Malicious', 'High'),
        3: ('Suspicious', 'Medium'),
        4: ('Common', 'Unknown'),
        5: ('Unknown', 'Unknown')
    }
    disposition_name = dis[disposition[0]][0]
    sever = dis[disposition[0]][1]
    res = {
        'type': 'judgement',
        'disposition': disposition[0],
        'observable': {'type': observable_type, 'value': observable_value},
        'disposition_name': disposition_name,
        'valid_time': valid_time,
        'priority': 90,
        'schema_version': '1.1.3',
        'confidence': 'High',
        'severity': sever,
        'source': 'generic api',
        'id': uuid
    }
    if(tlp != ''):
        res['tlp'] = tlp
    return res


def get_sightings(observable_value, observable_type, disposition, attribute):
    info = disposition['Event']['info']
    uuid = 'transient:sighting-'+disposition['Event']['uuid']
    timestamp = attribute['response']['Attribute'][0]['timestamp']
    event_id = attribute['response']['Attribute'][0]['event_id']
    x = str(datetime.utcfromtimestamp(int(timestamp)))
    time = x[:10]+'T'+x[11:]+'.000Z'
    return{
        'description': info,
        'type': 'sighting',
        'observables': [{'type': observable_type, 'value': observable_value}],
        'relations': get_relations(observable_value, observable_type,
                                   disposition),
        'schema_version': '1.1.3',
        'observed_time': {'start_time': time, 'end_time': time},
        'source': 'MISP Threat Sharing Analysis',
        'source_uri': current_app.config['API_URL']+'events/view/'+event_id,
        'count': 1,
        'confidence': 'High',
        'id': uuid,
        'timestamp': time
    }


def get_indicators(observable_value, observable_type, disposition, attribute,
                   valid_time, tlp):
    uuid = 'transient:indicators-'+disposition['Event']['uuid']
    org_id = disposition['Event']['Orgc']['name']
    info = disposition['Event']['info']
    event_id = attribute['response']['Attribute'][0]['event_id']
    res = {
        'id': uuid,
        'producer': org_id,
        'schema_version': '1.1.3',
        'type': 'indicator',
        'valid_time': valid_time,
        'confidence': 'High',
        'source': 'MISP Threat Sharing Analysis',
        'source_uri': current_app.config['API_URL']+'events/view/'+event_id,
        'short_description': info
    }
    if(tlp != ''):
        res['tlp'] = tlp
    return res


def get_relations(observable_value, observable_type, disposition):
    relations = []
    attribute = disposition['Event']['Attribute']
    observable_values = {
                         'url': 'url',
                         'ip-src': 'ip',
                         'sha256': 'sha256',
                         'domain': 'domain'
                         }
    d = {
        'origin': 'MISP Intelligence',
        'relation': 'related-to',
        'source': {'value': observable_value, 'type': observable_type},
    }
    x = {}
    for i in attribute:
        x = d.copy()
        if(i['type'] in observable_values and i['value'] != observable_value):
            x['related'] = {'value': i['value'],
                            'type': observable_values[i['type']]}
            relations.append(x)
    return relations


def get_relationships(sightings_id, indicator_id, disposition):
    uuid = 'transient:relationships-'+disposition['Event']['uuid']
    return{
        'id': uuid,
        'schema_version': '1.1.3',
        'type': 'relationship',
        'source_ref': sightings_id,
        'target_ref': indicator_id,
        'relationship_type': 'sighting-of'
    }


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    return jsonify([])


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    apikey = get_jwt()
    data = {}
    result = {}
    g.verdicts = []
    g.judgements = []
    g.sightings = []
    g.indicators = []
    g.relationships = []
    relay_input = get_json(ObservableSchema(many=True))
    observables = group_observables(relay_input)
    if not observables:
        return jsonify_data({})
    observables = build_input_api(observables)
    for observable in observables:
        o_type = observable['type'].lower()
        o_value = observable['value']
        (disposition, attribute) = call_api(o_type, o_value, apikey)
        if(disposition == {} and attribute == {}):
            continue
        disposition_tuple = get_disposition(disposition)
        if not disposition_tuple:
            continue
        start_time = datetime.utcnow()
        valid_time = {
            'start_time': start_time.isoformat() + 'Z',
        }
        if o_type == 'sha256':
            valid_time['end_time'] = '2525-01-01T00:00:00.000Z'
        else:
            end_time = start_time + timedelta(weeks=1)
            valid_time['end_time'] = end_time
        tlp = get_tlp(disposition, attribute)
        g.verdicts.append(get_verdict(o_value, o_type, disposition_tuple,
                          valid_time))
        g.judgements.append(get_judgement(o_value, o_type, disposition_tuple,
                            valid_time, disposition, attribute, tlp))
        sight = get_sightings(o_value, o_type, disposition, attribute)
        g.sightings.append(sight)
        indicate = get_indicators(o_value, o_type, disposition, attribute,
                                  valid_time, tlp)
        g.indicators.append(indicate)
        g.relationships.append(get_relationships(sight['id'], indicate['id'],
                               disposition))
        if g.verdicts:
            data['verdicts'] = format_docs(g.verdicts)
        if g.judgements:
            data['judgements'] = format_docs(g.judgements)
        if g.sightings:
            data['sightings'] = format_docs(g.sightings)
        if g.indicators:
            data['indicators'] = format_docs(g.indicators)
        if g.relationships:
            data['relationships'] = format_docs(g.relationships)
        result = {'data': data}
    return jsonify(result)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data([])
