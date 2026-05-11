import datetime, requests, typing


class IntellumHTTPError(Exception):
    def __init__(self, req : requests.Response, message : str):
        self.req = req
        super().__init__(f'HTTP ERROR {req.status_code} - {message}')


class InvalidJWTIssueTime(IntellumHTTPError):
    def __init__(self, req : requests.Response):
        super().__init__(req, 'Invalid JWT Issue Time (your clock speed may be ahead of the server, try increasing the time offset)')


class IncorrectJWTEncoding(IntellumHTTPError):
    def __init__(self, req : requests.Response):
        super().__init__(req, 'Incorrect JWT Encoding (failed to decode JWT, the provided private key is invalid)')


class InvalidClient(IntellumHTTPError):
    def __init__(self, req : requests.Response):
        super().__init__(req, f'Invalid Client (the {'prod' if '-staging' not in req.url else 'stage'}_app_uid in your config does not match any available on the server)')


class AccessTokenInvalid(IntellumHTTPError):
    def __init__(self, req : requests.Response):
        super().__init__(req, f'Access Token Invalid (the {'prod' if '-staging' not in req.url else 'stage'}_tok in your config is invalid)')


class AccessTokenExpired(IntellumHTTPError):
    def __init__(self, req : requests.Response):
        super().__init__(req, f'Access Token Expired (the {'prod' if '-staging' not in req.url else 'stage'}_tok in your config expired)')


class Unauthorized(IntellumHTTPError):
    def __init__(self, req : requests.Response):
        response : dict = req.json()
        self.api_version : str = response['api_version']
        self.error_type = 'list[dict[str, str]]'
        self.errors : list[dict[str, str]] = response['errors']
        super().__init__(req, f'API Version {self.api_version}\n{'\n'.join(f' - Error Description: {error["message"]}\n   HTTP Status: {error["status"]}\n   Failing Attribute: {error["source"]}' for error in self.errors)}')


class MalformedRequest(IntellumHTTPError):
    def __init__(self, req : requests.Response):
        super().__init__(req, f'Malformed API Request\nRequest: {req.url}')


class NotFound(IntellumHTTPError):
    def __init__(self, req : requests.Response):
        response : dict = req.json()
        self.api_version = response['api_version']
        if type(response['errors'][0]) is str:
            self.error_type = 'list[str]'
            self.errors : list[str] = response['errors']
            super().__init__(req, f'API Version {self.api_version}\n{'\n'.join(f' - {error}' for error in self.errors)}')
        else:
            self.error_type = 'list[dict[str, str]]'
            self.errors : list[dict[str, str]] = response['errors']
            super().__init__(req, f'API Version {self.api_version}\n{'\n'.join(f' - Error Description: {error["message"]}\n   HTTP Status: {error["status"]}\n   Failing Attribute: {error["source"]}' for error in self.errors)}')


class UnprocessableEntity(IntellumHTTPError):
    def __init__(self, req : requests.Response):
        response : dict = req.json()
        self.api_version : str = response['api_version']
        self.errors : list[str] | list[dict[str, str]] = []
        self.error_type : typing.Literal['list[str]', 'list[dict[str, str]]'] | None = None
        if type(response['errors'][0]) is str:
            self.error_type = 'list[str]'
            self.errors = response['errors']
            super().__init__(req, f'API Version {self.api_version}\n{'\n'.join(f' - {error}' for error in self.errors)}')
        else:
            self.error_type = 'list[dict[str, str]]'
            self.errors = response['errors']
            super().__init__(req, f'API Version {self.api_version}\n{'\n'.join(f' - Error Description: {error["message"]}\n   HTTP Status: {error["status"]}\n   Failing Attribute: {error["source"]}' for error in self.errors)}')


class NotModified(IntellumHTTPError):
    def __init__(self, req : requests.Response, if_modified_since : datetime.datetime):
        self.if_modified_since = if_modified_since
        super().__init__(req, f'Not Modified (no update performed on the root object or any associated objects because it has been modified since the specified date {if_modified_since.strftime('%Y-%m-%d %I:%M:%S %p %Z')})')