from api.errors import WatchdogError
from api.utils import jsonify_data
from flask import request, Blueprint

watchdog_api = Blueprint("watchdog", __name__)


@watchdog_api.route("/watchdog", methods=["GET"])
def watchdog():
    try:
        return jsonify_data(request.headers["Health-Check"])
    except KeyError:
        raise WatchdogError
