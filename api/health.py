from flask import Blueprint

from api.utils import get_jwt, jsonify_data
from api.errors import EmailRepNotFound
import requests

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    apikey = get_jwt()
    headers = {
        'Key': apikey
    }
    response = requests.get('https://emailrep.io/bill@microsoft.com',
                            headers=headers)
    if response.status_code == 200:
        return jsonify_data({'status': 'ok'})
    else:
        raise EmailRepNotFound('server is not responding')
