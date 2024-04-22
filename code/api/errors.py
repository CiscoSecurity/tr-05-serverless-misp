AUTH_ERROR = "authorization error"
INVALID_ARGUMENT = "invalid argument"
UNKNOWN = "unknown"
HEALTH_CHECK_ERROR = "health check failed"


class TRFormattedError(Exception):
    def __init__(self, code, message, type_="fatal"):
        super().__init__()
        self.code = code or UNKNOWN
        self.message = message or "Something went wrong."
        self.type_ = type_

    @property
    def json(self):
        return {"type": self.type_, "code": self.code, "message": self.message}


class AuthorizationError(TRFormattedError):
    def __init__(self, message):
        super().__init__(AUTH_ERROR, f"Authorization failed: {message}")


class InvalidArgumentError(TRFormattedError):
    def __init__(self, message):
        super().__init__(INVALID_ARGUMENT, f"Invalid JSON payload received. {message}")


class WatchdogError(TRFormattedError):
    def __init__(self):
        super().__init__(HEALTH_CHECK_ERROR, message="Invalid Health Check")


class CriticalMISPResponseError(TRFormattedError):
    def __init__(self, message):
        super().__init__(UNKNOWN, "Unexpected response from MISP: " + message)
