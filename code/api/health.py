from api.utils import get_key, jsonify_data
from flask import Blueprint, current_app
from pymisp import PyMISP, exceptions

from api.errors import CriticalMISPResponseError

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    try:
        _ = PyMISP(
            current_app.config['HOST'],
            get_key(),
            current_app.config['MISP_VERIFYCERT']
        )
    except exceptions.PyMISPError as error:
        raise CriticalMISPResponseError(error)

    return jsonify_data({'status': 'ok'})
