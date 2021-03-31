from functools import partial
import json
import requests
from flask import Blueprint, current_app, jsonify, g
from datetime import datetime, timedelta
from api.schemas import ObservableSchema
from api.utils import get_json, get_jwt, jsonify_data,jsonify_errors,format_docs
#from pymisp import PyMISP

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


#def init1(url,api):
 #   return PyMISP(url,api,False,'json')

def group_observables(relay_input):
    result=[]
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
    # formating, cleanup
    for observable in observables:
        o_value = observable['value']
        o_type = observable['type'].lower()
        if current_app.config['CCT_OBSERVABLE_TYPES'][o_type].get('sep'):
            o_value = o_value.split(
                current_app.config['CCT_OBSERVABLE_TYPES'][o_type]['sep'])[-1]
            observable['value'] = o_value
    return observables

def call_api(type,value,misp):
    headers={
    'Accept': 'application/json',
    'Connection': 'keep-alive',
    'Authorization' : misp,
    'Content-Type' : 'application/json',
    'Host': '54.236.45.79'
    }
    data={
        'responseFormat':'json'
    }
    observable_values={'url':'url','ip':'ip-src','sha256':'sha256','domain':'domain'}
    data['type']=observable_values[type]
    data['value']=value
    x=json.dumps(data)
    response = requests.post('https://100.27.2.155/attributes/restSearch',headers=headers,data=x,verify=False)
    res=response.json()
    if(len(res['response']['Attribute'])==0):
        return {}
    event_id = res['response']['Attribute'][0]['event_id']
    result = requests.get('https://100.27.2.155/events/view/'+event_id,headers=headers,data={},verify=False)
    return result.json()

def get_disposition(disposition):
    threat_id = disposition['Event']['threat_level_id']
    print(threat_id)
    if threat_id == '1':
        return current_app.config['DISPOSITIONS']['malicious']
    elif threat_id == '2':
        return current_app.config['DISPOSITIONS']['suspicious']
    elif threat_id == '3':
        print('clean')
        return current_app.config['DISPOSITIONS']['clean']
    else:
        print('unknown')
        return current_app.config['DISPOSITIONS']['unknown']

def get_verdict(observable_value, observable_type,disposition, valid_time):
    if disposition[0]==1:
        disposition_name='Clean'
    elif disposition[0]==2:
        disposition_name='Malicious'
    elif disposition[0]==3:
        disposition_name='Suspicious'
    elif disposition[0]==4:
        disposition_name='Common'
    elif disposition[0]==5:
        disposition_name='Unknown'        
    else:
        disposition_name='Unknown'         
    return {
        'type': 'verdict',
        'observable': {'type': observable_type, 'value': observable_value},
        'disposition': disposition[0],
        'disposition_name': disposition_name,
        'valid_time': valid_time
    }  

def get_judgement(observable_value,observable_type,disposition,valid_time,disp):
    uuid= disp['Event']['uuid']
    sever='Unknown'
    if disposition[0]==1:
        disposition_name='Clean'
        sever='Low'
    elif disposition[0]==2:
        disposition_name='Malicious'
        sever='High'
    elif disposition[0]==3:
        disposition_name='Suspicious'
        sever='Medium'
        print(sever)
    elif disposition[0]==4:
        disposition_name='Common'
        sever='Unknown'
    elif disposition[0]==5:
        disposition_name='Unknown'
        sever='Unknown'        
    return {
        'type':'judgement',
        'disposition':disposition[0],
        'observable': {'type': observable_type, 'value': observable_value},
        'disposition_name': disposition_name,
        'valid_time': valid_time,
        'priority':90,
        'schema_version':'1.1.3',
        'confidence':'High',
        'severity':sever,
        'source':'generic api',
        'id':uuid
    }

@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    print('hello')
    apikey= get_jwt()
    #misp=init1(current_app.config['API_URL'],apikey)
    data={}
    g.verdicts=[]
    relay_input = get_json(ObservableSchema(many=True))
    observables = group_observables(relay_input)
    if not observables:
        return jsonify_data({})
    observables = build_input_api(observables)
    for observable in observables:
        o_type = observable['type'].lower()
        o_value = observable['value']
        disposition = call_api(o_type,o_value,apikey)
        disposition_tuple = get_disposition(disposition)
        print(disposition_tuple)
        if not disposition_tuple:
            continue
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(weeks=1)
        valid_time = {
            'start_time': start_time.isoformat() + 'Z',
            'end_time': end_time.isoformat() + 'Z',
        }
        g.verdicts.append(get_verdict(o_value, o_type, disposition_tuple, valid_time))
        if g.verdicts:
            data['verdicts'] = format_docs(g.verdicts)
        result = {'data': data}
    return jsonify(result)

@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    apikey = get_jwt()
    data={}
    g.judgements=[]
    relay_input = get_json(ObservableSchema(many=True))
    observables = group_observables(relay_input)
    if not observables:
        return jsonify_data({})
    observables = build_input_api(observables)
    for observable in observables:
        o_type = observable['type'].lower()
        o_value = observable['value']
        disposition = call_api(o_type,o_value,apikey)
        disposition_tuple = get_disposition(disposition)
        if not disposition_tuple:
            continue
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(weeks=1)
        valid_time = {
            'start_time': start_time.isoformat() + 'Z',
            'end_time': end_time.isoformat() + 'Z',
        }
        g.judgements.append(get_judgement(o_value, o_type, disposition_tuple, valid_time,disposition))
        if g.judgements:
            data['judgements'] = format_docs(g.judgements)
        result = {'data': data}
    return jsonify(result)
  


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data([])
