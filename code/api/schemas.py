from marshmallow import ValidationError, Schema, fields, INCLUDE


def validate_string(value):
    if value == '':
        raise ValidationError('Field may not be blank.')


class ObservableSchema(Schema):
    type = fields.String(
        validate=validate_string,
        required=True,
    )
    value = fields.String(
        validate=validate_string,
        required=True,
    )


class ActionFormParamsSchema(Schema):
    action_id = fields.String(
        data_key='action-id',
        validate=validate_string,
        required=True,
    )
    observable_type = fields.String(
        validate=validate_string,
        required=True,
    )
    observable_value = fields.String(
        validate=validate_string,
        required=True,
    )

    class Meta:
        unknown = INCLUDE


class DashboardTileSchema(Schema):
    tile_id = fields.String(
        data_key='tile_id',
        validate=validate_string,
        required=True
    )


class DashboardTileDataSchema(Schema):
    period = fields.String(
        data_key='period',
        validate=validate_string,
        required=True
    )
    tile_id = fields.String(
        data_key='tile_id',
        validate=validate_string,
        required=True
    )
