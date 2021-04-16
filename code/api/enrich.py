from functools import partial

from api.schemas import ObservableSchema
from api.utils import get_json, get_key, jsonify_data
from flask import Blueprint, current_app, g
from pymisp import PyMISP, exceptions

from api.errors import CriticalMISPResponseError
from api.mappings import Mapping

from api.utils import jsonify_result

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    try:
        misp = PyMISP(
            key=get_key(),
            url=current_app.config['HOST'],
            ssl=current_app.config['MISP_VERIFYCERT'],
            tool=current_app.config['USER_AGENT']
        )
    except exceptions.PyMISPError as error:
        raise CriticalMISPResponseError(error.message)

    observables = get_observables()

    g.verdicts = []
    for ob in observables:
        mapping = Mapping(ob)

        events = misp.search(value=ob['value'], metadata=False)
        events.sort(key=lambda j: j['Event']['threat_level_id'])

        if events:
            g.verdicts.append(mapping.extract_verdict(events[0]['Event']))

    return jsonify_result()


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    try:
        misp = PyMISP(
            key=get_key(),
            url=current_app.config['HOST'],
            ssl=current_app.config['MISP_VERIFYCERT'],
            tool=current_app.config['USER_AGENT']
        )
    except exceptions.PyMISPError as error:
        raise CriticalMISPResponseError(error.message)

    observables = get_observables()

    g.verdicts = []
    g.judgements = []
    for observable in observables:
        mapping = Mapping(observable)

        events = misp.search(value=observable['value'], metadata=False)
        events.sort(key=lambda j: j['Event']['threat_level_id'])

        judgements_for_observable = []
        for event in events:
            judgements_for_observable.append(mapping.extract_judgement(
                event['Event']))

        if judgements_for_observable:
            g.judgements.extend(judgements_for_observable)
            verdict = mapping.extract_verdict(
                events[0]['Event']
            )
            verdict['judgement_id'] = judgements_for_observable[0]['id']
            g.verdicts.append(verdict)

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_key()
    _ = get_observables()
    return jsonify_data([])
