from api.utils import jsonify_data, create_misp_instance
from flask import Blueprint

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    _ = create_misp_instance()

    return jsonify_data({'status': 'ok'})
