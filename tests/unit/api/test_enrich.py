from http import HTTPStatus

from pytest import fixture

from .utils import get_headers


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json_value():
    return [{'type': 'ip', 'value': ''}]


def test_enrich_call_with_valid_jwt_but_invalid_json_value(
        route, client, valid_jwt, invalid_json_value,
        invalid_json_expected_payload
):
    response = client.post(route,
                           headers=get_headers(valid_jwt),
                           json=invalid_json_value)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload(
        "{0: {'value': ['Field may not be blank.']}}"
    )


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'cisco.com'}]


def test_enrich_call_success(route, client, valid_jwt, valid_json):
    response = client.post(route, headers=get_headers(valid_jwt),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
