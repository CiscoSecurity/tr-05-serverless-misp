from http import HTTPStatus

from pytest import fixture

from .utils import get_headers


def routes():
    yield '/respond/observables'
    yield '/respond/trigger'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture()
def invalid_json_value():
    return [{'type': 'ip', 'value': ''}]


@fixture()
def invalid_json_action_id():
    return {'action_id': 'some_action_id',
            'observable_type': 'domain',
            'observable_value': 'cisco.com'}


@fixture()
def invalid_json_observable_value():
    return {'action-id': 'some_action_id',
            'observable_type': 'ip',
            'observable_value': ''}


def test_respond_call_with_valid_jwt_but_invalid_json_value(
        client, valid_jwt, invalid_json_value,
        invalid_json_expected_payload, route='/respond/observables'
):
    response = client.post(route,
                           headers=get_headers(valid_jwt),
                           json=invalid_json_value)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload(
        "{0: {'value': ['Field may not be blank.']}}"
    )


def test_respond_call_with_valid_jwt_but_invalid_json_action_id(
        client, valid_jwt, invalid_json_action_id,
        invalid_json_expected_payload, route='/respond/trigger'
):
    response = client.post(route,
                           headers=get_headers(valid_jwt),
                           json=invalid_json_action_id)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload(
        "{'action-id': ['Missing data for required field.']}"
    )


def test_respond_call_with_valid_jwt_but_invalid_json_observable_value(
        client, valid_jwt, invalid_json_observable_value,
        invalid_json_expected_payload, route='/respond/trigger'
):
    response = client.post(route,
                           headers=get_headers(valid_jwt),
                           json=invalid_json_observable_value)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload(
        "{'observable_value': ['Field may not be blank.']}"
    )


@fixture(scope='module')
def valid_json(route):
    if route.endswith('/observables'):
        return [{'type': 'domain', 'value': 'cisco.com'}]

    if route.endswith('/trigger'):
        return {'action-id': 'valid-action-id',
                'observable_type': 'domain',
                'observable_value': 'cisco.com'}


def test_respond_call_success(route, client, valid_jwt, valid_json):
    response = client.post(route, headers=get_headers(valid_jwt),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
