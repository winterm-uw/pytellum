import json, jwt, requests
from . import exceptions
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import date, datetime
from email.utils import format_datetime
from typing import Any, Literal
from pathlib import Path
from time import time
from urllib.parse import quote, urlparse


def generate_key(output_dir_path : Path = Path('./keys')) -> tuple[Path, Path]:
    if output_dir_path.exists() and not output_dir_path.is_dir():
        raise FileExistsError(f'Output directory path "{output_dir_path.absolute()}" is invalid')
    output_dir_path.mkdir(exist_ok=True)
    created_t = int(time())
    private_key_f_path = output_dir_path / Path(f'{created_t}_private.key')
    public_key_f_path = output_dir_path / Path(f'{created_t}_public.key.pub')

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(private_key_f_path, 'x') as private_key_f:
        private_key_f.write(pem_private_key.decode())
    with open(public_key_f_path, 'x') as public_key_f:
        public_key_f.write(pem_public_key.decode())
    
    return private_key_f_path, public_key_f_path


def _interpret_parameter_value(parameter) -> list[str] | str | None:
    match parameter:
        case str():
            return parameter
        case bool():
            return 'true' if parameter else 'false'
        case int():
            return str(parameter)
        case date():
            return str(parameter)
        case datetime():
            return parameter.isoformat() if parameter.tzinfo is not None else f'{parameter.isoformat()}+00:00'
        case list():
            if len(parameter) == 0:
                return None
            return [_interpret_parameter_value(i) for i in parameter]
        case _:
            raise TypeError(f'Cannot parse query parameter of type "{type(parameter)}"')

def _interpret_query_parameters(parameters : dict[str, Any]) -> str:
    if len(parameters) < 1:
        return ''
    return '&'.join((f'{key}={quote(_interpret_parameter_value(value))}' if type(value) is not list else (f'&{'&'.join(f'{key}[]={quote(v)}' for v in value)}')) for key, value in parameters.items() if value is not None)

def _test_intellum_http_exceptions(req : requests.Response, if_modified_since : datetime | None = None):
    is_json = True
    try:
        content = req.json()
    except json.JSONDecodeError:
        is_json = False
        content = req.content
    
    match req.status_code:
        case n if n // 100 == 2:
            return
        case 400:
            if content['error'] == 'incorrect_jwt_encoding':
                raise exceptions.IncorrectJWTEncoding(req)
            raise exceptions.InvalidJWTIssueTime(req)
        case 401:
            if isinstance('error' in content.keys()):
                raise exceptions.InvalidClient(req)
            if isinstance(content['errors'][0], str):
                if 'Unauthorized: The access token expired' in content['errors']:
                    raise exceptions.AccessTokenExpired(req)
                else:
                    raise exceptions.AccessTokenInvalid(req)
            raise exceptions.Unauthorized(req)
        case 404:
            if is_json:
                raise exceptions.NotFound(req)
            else:
                raise exceptions.MalformedRequest(req)
        case 422:
            raise exceptions.UnprocessableEntity(req)
        case 304:
            raise exceptions.NotModified(req, if_modified_since)
        case _:
            raise exceptions.IntellumHTTPError(req, content)


class CursorIndexResults:
    def __init__(self, api : API, object_type : str, **parameters):
        self.api = api
        self.object_type = object_type
        self.parameters = parameters
        self.content : list[dict] = []
        self.page_token : str | None = ''
        self.notices : list[str] = []
        self.api_version : str = ''
    
    @property
    def complete(self) -> bool:
        return self.page_token is None
    
    def __iter__(self):
        return self
    
    def __next__(self):
        return self.next()
    
    def next(self) -> list[dict]:
        if not self.complete:
            results = self.api.get_req(f'{self.object_type}?pagination=cursor&page_token={self.page_token}{f'&{_interpret_query_parameters(self.parameters)}' if len(self.parameters) else ''}').json()

            self.page_token = results['pagination']['next_page_token']
            if 'notices' in results.keys():
                self.notices.extend(results['notices'])
            self.api_version = results['api_version']
            items : list[dict] = results[next(key for key in results.keys() if key not in ('pagination', 'notices', 'api_version'))]
            self.content.extend(items)
            return items
        raise StopIteration()
    
    def all(self, print_loaded_records_to_console : bool = False) -> list[dict]:
        while not self.complete:
            next(self)
            if print_loaded_records_to_console:
                print(f'Records Loaded: {len(self.content)}')
        return self.content


class NumericIndexResults:
    def __init__(self, api : API, object_type : str, **parameters):
        self.api = api
        self.object_type = object_type
        self.parameters = parameters

        self.api_version : str = ''
        self.notices : set[str] = set()
        self.content : list[dict] = []

        self.current_page = -1
        self.total_pages = 0
        self.records_per_page = 0
        self.total_records = 0

        self._t_init = 0
        self._t_curr = 0
    
    @property
    def complete(self) -> bool:
        return self.current_page >= self.total_pages
    
    @property
    def delta_t(self) -> int:
        return self._t_curr - self._t_init
    
    @property
    def pages_remaining(self) -> int:
        return self.total_pages - self.current_page
    
    @property
    def current_rate(self) -> float:
        return self.current_page / self.delta_t if self.delta_t > 0 else 0.0
    
    @property
    def seconds_to_finish(self) -> int:
        return int(self.current_rate * self.pages_remaining)
    
    @property
    def estimated_completion_time_pretty(self) -> str:
        return f'{self.seconds_to_finish // 60}m {self.seconds_to_finish % 60}s'
    
    def __iter__(self):
        return self
    
    def __next__(self):
        return self.next()
    
    def next(self) -> list[dict]:
        if self.current_page < 0:
            self._t_init = int(time())
            self.current_page = 0
        
        if self.current_page < self.total_pages:
            self.current_page += 1
            results : dict = self.api.get_req(f'{self.object_type}?page={self.current_page}{f'&{_interpret_query_parameters(self.parameters)}' if len(self.parameters) else ''}').json()
            self._t_curr = int(time())
            self.api_version = results['api_version']
            self.notices.union(results['notices'])
            self.total_pages = results['pagination']['total_pages']
            self.records_per_page = results['pagination']['records_per_page']
            self.total_records = results['pagination']['total_records']
            records =  results[next(key for key in results.keys() if key not in ('api_version', 'notices', 'pagination'))]
            self.content.extend(records)
            return records
        raise StopIteration()
    
    def all(self, print_status_to_console : bool = False) -> list[dict]:
        while next(self, None):
            if print_status_to_console:
                print(f'Estimated Completion Time: {self.estimated_completion_time_pretty}')
        return self.content


class ReadResult:
    def __init__(self, api : API, object_type : str,  id : int | str, **parameters):
        self.api = api
        self.object_type = object_type
        self.id = id
        self.parameters = parameters

        self._t_init = int(time())
        result : dict = api.get_req(f'{self.object_type}/{self.id}{f'?{_interpret_query_parameters(self.parameters)}' if self.parameters else ''}').json()
        self._t_final = int(time())

        self.delta_t = self._t_final - self._t_init
        self.notices : list[str] = result['notices'] if 'notices' in result.keys() else []
        self.api_version : str = result['api_version']
        self.content : dict = result[next(key for key in result.keys() if key not in ('api_version', 'notices'))]


class CreateResult:
    def __init__(self, api : API, object_type : str, data : dict,  id : int | str | None = None, **parameters):
        self.api = api
        self.object_type = object_type
        self.data = data
        self.id = id
        self.parameters = parameters

        self._t_init = int(time())
        query_parameters = _interpret_query_parameters(self.parameters)
        result : dict = api.post_req(f'{self.object_type % id if id is not None else self.object_type}{f'?{query_parameters}' if query_parameters else ''}', data).json()
        self._t_final = int(time())

        self.delta_t = self._t_final - self._t_init
        self.notices : list[str] = result['notices'] if 'notices' in result.keys() else []
        self.api_version : str = result['api_version']
        self.changed_records : dict = result['status_messages']['changed'] if 'status_messages' in result.keys() and 'changed' in result['status_messages'].keys() else {}
        self.created_records : dict = result['status_messages']['created'] if 'status_messages' in result.keys() and 'created' in result['status_messages'].keys() else {}
        self.deleted_records : dict = result['status_messages']['deleted'] if 'status_messages' in result.keys() and 'deleted' in result['status_messages'].keys() else {}
        self.content : dict = result[next(key for key in result.keys() if key not in ('api_version', 'notices', 'status_messages'))]


class UpdateResult:
    def __init__(self, api : API, object_type : str, data : dict,  id : int | str | None = None, if_unmodified_since : datetime | None = None, **parameters):
        self.api = api
        self.object_type = object_type
        self.data = data
        self.id = id
        self.parameters = parameters
        self.if_unmodified_since = if_unmodified_since

        self._t_init = int(time())
        query_parameters = _interpret_query_parameters(self.parameters)
        try:
            result = api.put_req(f'{self.object_type % id if id is not None else self.object_type}{f'?{query_parameters}' if query_parameters else ''}', data, if_unmodified_since).json()
        except exceptions.NotModified:
            self.content = None
            return
        finally:
            self._t_final = int(time())
            self.delta_t = self._t_final - self._t_init
        
        self.notices : list[str] = result['notices'] if 'notices' in result.keys() else []
        self.api_version : str = result['api_version']
        self.changed_records : dict = result['status_messages']['changed'] if 'status_messages' in result.keys() and 'changed' in result['status_messages'].keys() else {}
        self.created_records : dict = result['status_messages']['created'] if 'status_messages' in result.keys() and 'created' in result['status_messages'].keys() else {}
        self.deleted_records : dict = result['status_messages']['deleted'] if 'status_messages' in result.keys() and 'deleted' in result['status_messages'].keys() else {}
        self.content : dict = result[next(key for key in result.keys() if key not in ('api_version', 'notices', 'status_messages'))]


class DeleteResult:
    def __init__(self, api : API, object_type : str, id : int | str, **parameters):
        self.api = api
        self.object_type = object_type
        self.id = id
        self.parameters = parameters

        self._t_init = int(time())
        req = api.del_req(f'{self.object_type}/{self.id}{f'?{_interpret_query_parameters(parameters)}' if len(self.parameters) else ''}',)
        self._t_final = int(time())

        self.delta_t = self._t_final - self._t_init
        self.success = req.status_code == 204


class API:
    def __init__(self, env : Literal['prod', 'stage'] = 'stage', config_file_path : Path = Path('config.json'), keys_directory_path : Path = Path('./keys'), time_offset : int = 0, permissions : list[Literal['admin_read', 'admin_write', 'user_tokens', 'ai_agent', 'super_admin']] = ['admin_read', 'admin_write']):
        self.config_f_path = config_file_path
        self.keys_dir_path = keys_directory_path
        self._config = None
        self.get_config()
        self.time_offset = time_offset
        self._time_offset_change_attempts = 0
        self.env : Literal['prod', 'stage'] = env
        self.permissions = permissions

        self._tokens : dict[str, str | int] = {
            'stage_tok': '',
            'prod_tok': '',
            'stage_tok_exp': 0,
            'prod_tok_exp': 0
        }

        if not self.get_config()['subdomain']:
            print(f'Please enter a subdomain in the config at {config_file_path.absolute()}')

        try:
            self.get_req('users?records_per_page=1&pagination=cursor')
        except requests.exceptions.ConnectionError:
            print(f'Failed to resolve https://{self.get_config()['subdomain']}.exceedlms{'-staging' if not self.prod else ''}.com - check internet connection')
            exit()
        except jwt.exceptions.InvalidKeyError:
            private_key_f_path = self.keys_dir_path / Path(f'{env}.key')
            print(f'Provided private key in {private_key_f_path.absolute()} is not of PEM format. Provide the correct private key or generate a new private/public key pair and configure it on the server')
            exit()


    @property
    def prod(self) -> bool:
        return self.env == 'prod'
    
    @prod.setter
    def prod(self, value : bool):
        self.env = 'prod' if value else 'stage'
    
    @prod.setter
    def prod(self, value : bool):
        key_f_path = self.keys_dir_path / Path(f'{'prod' if value else 'stage'}.key')
        if not key_f_path.is_file():
            raise FileNotFoundError(f'Private key file not found in directory: {key_f_path.absolute()}')
        self._prod = value
    
    def index(self, object_type : Literal['admin_permissions', 'assessment_question_sections', 'assessment_responses', 'category_follows', 'category_parents', 'course_facilitators', 'course_sessions', 'courses', 'courses/deletions', 'enrollment_proctoring_results', 'enrollments', 'enrollments/deletions', 'entity_status_history', 'flaggings', 'group_admins', 'group_members', 'groups', 'learner_permissions', 'on_demand_videos', 'organization_video_permissions', 'purchase_codes', 'purchases', 'reputation_earned_events', 'smart_links', 'taxonomy_items', 'user_certifications', 'users', 'users/deletions'] | str, pagination_method : Literal['cursor', 'numeric'] = 'cursor', **parameters):
        match pagination_method:
            case 'cursor':
                return CursorIndexResults(self, object_type, **parameters)
            case 'numeric':
                return NumericIndexResults(self, object_type, **parameters)
    
    def read(self, object_type : Literal['assessment_question_sections', 'assessment_responses', 'categories', 'category_follows', 'category_translations', 'course_sessions', 'courses', 'database_schema', 'enrollments', 'flaggings', 'group_admins', 'group_members', 'groups', 'purchase_codes', 'purchases', 'smart_links', 'taxonomy_items', 'users'] | str, id : int | str, **parameters):
        return ReadResult(self, object_type, id, **parameters)
    
    def create(self, object_type : Literal['admin_permissions', 'assessment_question_sections', 'assessment_responses', 'categories', 'category_follows', 'category_translations', 'course_facilitators', 'course_sessions', 'course_translations/%i', 'course_translations/%i/evolve_sync', 'courses', 'course_files', 'course_urls', 'course_self_posts', 'course_curricula', 'course_assessments', 'course_collections', 'course_pages', 'course_scorms', 'course_evolves', 'course_aiccs', 'enrollments', 'gamification_gold/debit', 'gamification_gold/credit', 'group_admins', 'group_members', 'groups', 'level_gold/debit', 'level_gold/credit', 'on_demand_videos', 'organization_video_permissions', 'purchase_codes', 'smart_links', 'taxonomy_items', 'user_tokens', 'users'] | str, data : dict, id : int | str | None = None, **parameters):
        return CreateResult(self, object_type, data, id, **parameters)
    
    def update(self, object_type : Literal['admin_permissions/%i', 'assessment_question_sections/%i', 'categories/%i', 'category_follows/%i', 'category_parents/%i', 'category_translations/%i', 'course_sessions/%i', 'course_translations/%i', 'courses/%i', 'course_files/%i', 'course_urls/%i', 'course_self_posts/%i', 'course_curricula/%i', 'course_assessments/%i', 'course_collections/%i', 'course_pages/%i', 'course_scorms/%i', 'course_evolves/%i', 'course_aiccs/%i', 'enrollments/%i', 'group_admins/%i', 'groups/%i', 'learner_permissions/update_permissions', 'on_demand_videos/%i', 'organization_video_permissions/%i', 'purchase_codes/%i', 'smart_links/%i', 'taxonomy_items/%i', 'taxonomy_items/order', 'users/%i'] | str, data : dict, id : int | str | None = None, if_unmodified_since : datetime | None = None, **parameters):
        return UpdateResult(self, object_type, data, id, if_unmodified_since, **parameters)
    
    def delete(self, object_type : Literal['admin_permissions', 'assessment_question_sections', 'categories', 'category_follows', 'course_facilitators', 'course_sessions', 'course_translations', 'courses', 'enrollments', 'group_admins', 'group_members', 'groups', 'live_videos', 'on_demand_videos', 'purchase_codes', 'smart_links', 'taxonomy_items', 'users'] | str, id : int | str, **parameters):
        return DeleteResult(self, object_type, id, **parameters)
    
    def get_config(self) -> dict[str, str | int]:
        if self._config:
            return self._config
        
        if not self.config_f_path.exists():
            self._config = {
                'api_version': 3,
                'subdomain': '',
                'prod_app_uid': '',
                'stage_app_uid': ''
            }
            with open(self.config_f_path, 'x') as config_f:
                json.dump(self._config, config_f, indent=4)
        
        with open(self.config_f_path, 'r') as config_f:
            self._config = json.load(config_f)
            return self._config
    
    def update_config(self, value : dict[str, str | int]):
        self._config.update(value)
        
        with open(self.config_f_path, 'w') as config_f:
            json.dump(self._config, config_f, indent=4)
    
    def _generate_token(self) -> str:
        env = 'prod' if self.prod else 'stage'
        app_uid = self.get_config()[f'{env}_app_uid']

        if not app_uid:
            print(f'{env}_app_uid not entered in config file at {self.config_f_path.absolute()}')
            exit()
        
        private_key_f_path = self.keys_dir_path / Path(f'{env}.key')
        private_key_f_path.parent.mkdir(exist_ok=True)

        if not private_key_f_path.exists() or not private_key_f_path.is_file():
            print(f'Private key not found at {private_key_f_path.absolute()}')
            exit()
        
        with open(private_key_f_path, 'r') as private_key_f:
            private_key = private_key_f.read()
        
        uri = urlparse(f'https://{self.get_config()['subdomain']}.exceedlms{'-staging' if not self.prod else ''}.com/oauth2/token.json')

        t = int(time()) - self.time_offset
        claim_set = {
            'iss': app_uid,
            'aud': f'{uri.scheme}://{uri.hostname}',
            'scope': ' '.join(self.permissions),
            'exp': t + 60,
            'iat': t
        }

        encoded_jwt = jwt.encode(claim_set, private_key, algorithm='RS256')

        try:
            req = requests.post(uri.geturl(), data={
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'assertion': encoded_jwt
            })
            _test_intellum_http_exceptions(req)
        except exceptions.InvalidJWTIssueTime:
            if self._time_offset_change_attempts >= 3:
                print('Failed to sync time automattically with offset.')
                exit()
            print('The JWT issue time is invalid, attempting to add 3 seconds to time_offset...')
            self.time_offset += 3
            self._time_offset_change_attempts += 1
            return self._generate_token()
        except exceptions.IncorrectJWTEncoding:
            print(f'The private key in {(self.keys_dir_path / Path(f'{self.env}.key')).absolute()} is incorrect and could not be used to decode the JWT provided by intellum.')
            exit()
        except exceptions.InvalidClient:
            print(f'The {self.env}_app_uid in {self.config_f_path.absolute()} does not match any configured the {self.get_config()['subdomain']} intellum server')
            exit()
        
        response = req.json()
        tok = response['access_token']
        tok_exp = response['created_at'] + response['expires_in'] - self.time_offset
        self._tokens.update({
            f'{env}_tok': tok,
            f'{env}_tok_exp': tok_exp
        })

        return tok
    
    @property
    def _token(self) -> str:
        env = 'prod' if self.prod else 'stage'
        tok : str = self._tokens[f'{env}_tok']
        tok_exp : int = self._tokens[f'{env}_tok_exp']
        if not tok or int(time()) >= tok_exp - self.time_offset:
            tok = self._generate_token()
        return tok
    
    @property
    def _api_base_url(self) -> str:
        return f'https://{self.get_config()['subdomain']}.exceedlms{'-staging' if not self.prod else ''}.com/api/v{self.get_config()['api_version']}'
    
    def get_req(self, url : str) -> requests.Response:
        uri = urlparse(f'{self._api_base_url}/{url}')
        req = requests.get(uri.geturl(), headers={'Authorization': f'Bearer {self._token}'})
        _test_intellum_http_exceptions(req)
        return req

    def post_req(self, url : str, data : dict) -> requests.Response:
        uri = urlparse(f'{self._api_base_url}/{url}')
        req = requests.post(uri.geturl(), json=data, headers={
            'Content-Type': 'application/json', 'Authorization': f'Bearer {self._token}'
        })
        _test_intellum_http_exceptions(req)
        return req
    
    def put_req(self, url : str, data : dict, if_unmodified_since : datetime | None = None) -> requests.Response:
        uri = urlparse(f'{self._api_base_url}/{url}')
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self._token}'
        }
        if if_unmodified_since is not None:
            headers['If-Unmodified-Since'] = format_datetime(if_unmodified_since, True)
        req = requests.put(uri.geturl(), json=data, headers=headers)
        _test_intellum_http_exceptions(req, if_unmodified_since)
        return req
    
    def del_req(self, url : str) -> requests.Response:
        uri = urlparse(f'{self._api_base_url}/{url}')
        req = requests.delete(uri.geturl(), headers={
            'Authorization': f'Bearer {self._token}'
        })
        _test_intellum_http_exceptions(req)
        return req