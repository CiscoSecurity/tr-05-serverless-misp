from http import HTTPStatus

from pytest import fixture


def routes():
    yield '/version'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def version_expected_payload(client):
    app = client.application
    return {'version': app.config['VERSION']}


def test_version_call_success(route, client, version_expected_payload):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == version_expected_payload
