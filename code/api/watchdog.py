from api.utils import jsonify_data
from flask import request, Blueprint
from api.errors import WatchdogError

watchdog_api = Blueprint('watchdog', __name__)


@watchdog_api.route('/watchdog', methods=['GET'])
def watchdog():
    try:
        watchdog_key = request.headers['Health-Check']
        return jsonify_data(watchdog_key)
    except KeyError:
        raise WatchdogError
