from flask import Blueprint, current_app

from api.utils import get_jwt, jsonify_data
from api.errors import MispNotFoundError

import requests
health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    apikey = get_jwt()
    headers = {
                'Accept': 'application/json',
                'Connection': 'keep-alive',
                'Authorization': apikey,
                'Content-Type': 'application/json'
    }
    try:
        response = requests.get(current_app.config['API_URL']
                                + 'servers/getVersion',
                                headers=headers,
                                verify=False,
                                timeout=3)
        if response.status_code == 200:
            return jsonify_data({'status': 'ok'})
        elif response.status_code == 404:
            raise MispNotFoundError('Please Check URL')
    except requests.exceptions.ConnectTimeout as e:
        raise MispNotFoundError(str(e))
