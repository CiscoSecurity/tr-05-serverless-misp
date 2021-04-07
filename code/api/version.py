from flask import Blueprint, jsonify, current_app

version_api = Blueprint('version', __name__)


@version_api.route('/version', methods=['POST'])
def version():
    return jsonify({'version': current_app.config['VERSION']})
