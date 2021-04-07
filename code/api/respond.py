from flask import Blueprint
from functools import partial
from api.utils import get_json, get_jwt, jsonify_data
from api.schemas import ObservableSchema, ActionFormParamsSchema

respond_api = Blueprint('respond', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))
get_action_form_params = partial(get_json, schema=ActionFormParamsSchema())


@respond_api.route('/respond/observables', methods=['POST'])
def respond_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data([])


@respond_api.route('/respond/trigger', methods=['POST'])
def respond_trigger():
    _ = get_jwt()
    _ = get_action_form_params()
    return jsonify_data({'status': 'success'})
