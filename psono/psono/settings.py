"""
Django settings for psono project.

Generated by 'django-admin startproject' using Django 1.8.3.

For more information on this file, see
https://docs.djangoproject.com/en/1.8/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.8/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import socket
import os
import sys
import yaml
import toml
import json
import hashlib
import nacl.encoding
import nacl.signing
import binascii
import base64
from decimal import Decimal
from urllib.parse import urlparse
from corsheaders.defaults import default_headers
from yubico_client.yubico import DEFAULT_API_URLS as DEFAULT_YUBICO_API_URLS
import dj_database_url


try:
    # Fall back to psycopg2cffi
    from psycopg2cffi import compat
    compat.register()
except ImportError:
    import psycopg2

def eprint_and_exit_gunicorn(error_message):
    print(f"ERROR: {error_message}", file=sys.stderr)
    sys.exit(4)


ENV_VAR_HOME = "PSONO_HOME"

CONFIG_FORMATS = ["yaml", "toml"]

ENV_FILE_ACCESS = ["SECRET_KEY", "ACTIVATION_LINK_SECRET", "DB_SECRET", 
"EMAIL_SECRET_SALT", "PRIVATE_KEY", "PUBLIC_KEY", 
"EMAIL_HOST_USER", "EMAIL_HOST_PASSWORD", "DATABASES_DEFAULT_NAME", 
"DATABASES_DEFAULT_PASSWORD", "DATABASES_DEFAULT_USER"]

def get_home_path():
    home_override = os.environ.get(ENV_VAR_HOME, '')
    home_path = os.path.expanduser('~')
    root_home = '/root'

    for p in [home_override, home_path, root_home]:
        for cf in CONFIG_FORMATS:
            config_path = os.path.join(p, '.psono_server', f'settings.{cf}')

            if os.path.exists(config_path):
                return p, config_path

    return eprint_and_exit_gunicorn(f"Could not detect HOME, you can specify it with {ENV_VAR_HOME} and check that it contains .psono_server/settings.yaml")

ENV_VAR_SERVER_SETTING_BASE64 = 'PSONO_SERVER_SETTING_BASE64'
ENV_VAR_SERVER_SETTING_TOML_BASE64 = 'PSONO_SERVER_SETTING_TOML_BASE64'

def deserialize_config(raw: str, config_format: str) -> dict:
    if config_format == "yaml":
        config = yaml.safe_load(raw)
    elif config_format == "toml":
        config = toml.loads(raw)
    else:
        raise Exception("unknown config format")

    return config

def load_config(config_path: str):
    settings_override = os.environ.get(ENV_VAR_SERVER_SETTING_BASE64, '')
    settings_override_toml = os.environ.get(ENV_VAR_SERVER_SETTING_TOML_BASE64, '')

    if settings_override:
        try:
            config_raw = base64.b64decode(settings_override).decode()
        except Exception as e:
            return eprint_and_exit_gunicorn(f"{ENV_VAR_SERVER_SETTING_BASE64} base64 decoding failed: {e}")

        config_source = ENV_VAR_SERVER_SETTING_BASE64
        config_format = "yaml"
    elif settings_override_toml:
        try:
            config_raw = base64.b64decode(settings_override_toml).decode()
        except Exception as e:
            return eprint_and_exit_gunicorn(f"{ENV_VAR_SERVER_SETTING_TOML_BASE64} base64 decoding failed: {e}")

        config_source = ENV_VAR_SERVER_SETTING_TOML_BASE64
        config_format = "toml"
    else:
        try:
            with open(config_path, 'r') as stream:
                config_raw = stream.read()
        except Exception as e:
            return eprint_and_exit_gunicorn(f"loading config from '{config_path}' failed: {e}")

        config_source = config_path
        _, config_ext = os.path.splitext(config_path)
        if config_ext == ".yaml":
            config_format = "yaml"
        elif config_ext == ".toml":
            config_format = "toml"
        else:
            return eprint_and_exit_gunicorn("unknown config format")

    try:
        config = deserialize_config(config_raw, config_format)
    except Exception as e:
        return eprint_and_exit_gunicorn(f"deserializing {config_format} config from '{config_source}' failed: {e}")

    if not isinstance(config, dict):
        return eprint_and_exit_gunicorn(f"config from '{config_source}' is empty or not a dict")

    return config


HOME, CONFIG_PATH = get_home_path()
CONFIG = load_config(CONFIG_PATH)

def config_get(key, *args):
    if 'PSONO_' + key in os.environ:
        val = os.environ.get('PSONO_' + key)
        try:
            json_object = json.loads(val)
        except ValueError:
            return val
        return json_object
    elif 'PSONO_' + key + '_FILE' in os.environ and key in ENV_FILE_ACCESS:
        p_file = os.environ.get('PSONO_' + key + '_FILE')  
        if os.path.exists(p_file) and os.path.getsize(p_file) > 0:
            try:
                with open(p_file) as f:
                    val = f.readline()
            except EnvironmentError:
                raise Exception("Setting not reading", "Couldn't read the setting for PSONO_%s_FILE (check file)" % (key,))
            return val
    if key in CONFIG:
        return CONFIG.get(key)
    if len(args) > 0:
        return args[0]
    raise Exception("Setting missing", "Couldn't find the setting for %s (maybe you forgot the 'PSONO_' prefix in the environment variable)" % (key,))

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

with open(os.path.join(BASE_DIR, 'VERSION.txt')) as f:
    VERSION = f.readline().rstrip()


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.8/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config_get('SECRET_KEY')
PRIVATE_KEY  = config_get('PRIVATE_KEY')
PUBLIC_KEY  = config_get('PUBLIC_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = str(config_get('DEBUG', False)).lower() == 'true'

DISABLED = str(config_get('DISABLED', False)).lower() == 'true'
MAINTENANCE_ACTIVE = str(config_get('MAINTENANCE_ACTIVE', False)).lower() == 'true'

ALLOWED_HOSTS = config_get('ALLOWED_HOSTS', ['*'])
if isinstance(ALLOWED_HOSTS, str):
    ALLOWED_HOSTS = [allowed_host_single.strip() for allowed_host_single in ALLOWED_HOSTS.split(',')]

ALLOWED_DOMAINS = config_get('ALLOWED_DOMAINS', [])
if isinstance(ALLOWED_DOMAINS, str) and ALLOWED_DOMAINS:
    ALLOWED_DOMAINS = [allowed_domains_single.strip() for allowed_domains_single in ALLOWED_DOMAINS.split(',')]

SERVICE_NAME = config_get('SERVICE_NAME', 'Psono')

ALLOW_REGISTRATION = str(config_get('ALLOW_REGISTRATION', True)).lower() == 'true'
ALLOW_LOST_PASSWORD = str(config_get('ALLOW_LOST_PASSWORD', True)).lower() == 'true'
ENFORCE_MATCHING_USERNAME_AND_EMAIL = str(config_get('ENFORCE_MATCHING_USERNAME_AND_EMAIL', False)).lower() == 'true'

ALLOWED_SECOND_FACTORS = config_get('ALLOWED_SECOND_FACTORS', ['yubikey_otp', 'webauthn', 'google_authenticator', 'duo'])
if isinstance(ALLOWED_SECOND_FACTORS, str) and ALLOWED_SECOND_FACTORS:
    ALLOWED_SECOND_FACTORS = [second_factor.strip() for second_factor in ALLOWED_SECOND_FACTORS.split(',')]
elif isinstance(ALLOWED_SECOND_FACTORS, str):
    ALLOWED_SECOND_FACTORS = []

ALLOW_USER_SEARCH_BY_EMAIL = str(config_get('ALLOW_USER_SEARCH_BY_EMAIL', False)).lower() == 'true'
ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL = str(config_get('ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL', False)).lower() == 'true'

DUO_INTEGRATION_KEY = config_get('DUO_INTEGRATION_KEY', '')
DUO_SECRET_KEY = config_get('DUO_SECRET_KEY', '')
DUO_API_HOSTNAME = config_get('DUO_API_HOSTNAME', '')

DUO_PROXY_HOST = config_get('DUO_PROXY_HOST', None)
DUO_PROXY_PORT = config_get('DUO_PROXY_PORT', None)
DUO_PROXY_HEADERS = config_get('DUO_PROXY_HEADERS', None)
DUO_PROXY_TYPE = config_get('DUO_PROXY_TYPE', None)  # CONNECT

MULTIFACTOR_ENABLED = str(config_get('MULTIFACTOR_ENABLED', False)).lower() == 'true'

REGISTRATION_EMAIL_FILTER = config_get('REGISTRATION_EMAIL_FILTER', [])
if isinstance(REGISTRATION_EMAIL_FILTER, str) and REGISTRATION_EMAIL_FILTER:
    REGISTRATION_EMAIL_FILTER = [single_registration_email_filter.strip() for single_registration_email_filter in REGISTRATION_EMAIL_FILTER.split(',')]

for index in range(len(REGISTRATION_EMAIL_FILTER)):
    REGISTRATION_EMAIL_FILTER[index] = REGISTRATION_EMAIL_FILTER[index].lower().strip()

for index in range(len(ALLOWED_SECOND_FACTORS)):
    ALLOWED_SECOND_FACTORS[index] = ALLOWED_SECOND_FACTORS[index].lower().strip()

MANAGEMENT_COMMAND_ACCESS_KEY = config_get('MANAGEMENT_COMMAND_ACCESS_KEY', '')

HOST_URL = config_get('HOST_URL')

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'anymail',
    'corsheaders',
    'rest_framework',
    'restapi',
    'administration',
    'fileserver',
    'credit',
]

MIDDLEWARE = (
    'django.middleware.security.SecurityMiddleware',
    'restapi.middleware.DisableMiddleware',
    'restapi.middleware.MaintenanceMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

PASSWORD_HASHERS = (
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
    'django.contrib.auth.hashers.BCryptPasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher'
)

TRUSTED_COUNTRY_HEADER = config_get('TRUSTED_COUNTRY_HEADER', None)  # e.g. HTTP_CF_IPCOUNTRY
TRUSTED_IP_HEADER = config_get('TRUSTED_IP_HEADER', None)  # e.g. HTTP_CF_CONNECTING_IP

NUM_PROXIES = config_get('NUM_PROXIES', None)
if NUM_PROXIES is not None:
    NUM_PROXIES = int(NUM_PROXIES)

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAdminUser',
    ),
    'DEFAULT_PARSER_CLASSES': (
        'restapi.parsers.DecryptJSONParser',
        # 'rest_framework.parsers.FormParser', # default for Form Parsing
        'rest_framework.parsers.MultiPartParser', # default for UnitTest Parsing
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'restapi.renderers.EncryptJSONRenderer',
        # 'rest_framework.renderers.BrowsableAPIRenderer',
    ),
    'DEFAULT_THROTTLE_CLASSES': (
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
        'rest_framework.throttling.ScopedRateThrottle',
    ),
    'DEFAULT_THROTTLE_RATES': {
        'anon': config_get('THROTTLE_RATE_ANON', '1440/day'),
        'prelogin': config_get('THROTTLE_RATE_PRE_LOGIN', '48/day'),
        'login': config_get('THROTTLE_RATE_LOGIN', '48/day'),
        'link_share_secret': config_get('THROTTLE_RATE_LINK_SHARE_SECRET', '60/hour'),
        'password': config_get('THROTTLE_RATE_PASSWORD', '24/day'),
        'user': config_get('THROTTLE_RATE_USER', '86400/day'),
        'health_check': config_get('THROTTLE_RATE_HEALTH_CHECK', '61/hour'),
        'status_check': config_get('THROTTLE_RATE_STATUS_CHECK', '6/minute'),
        'ga_verify': config_get('THROTTLE_RATE_GA_VERIFY', '6/minute'),
        'duo_verify': config_get('THROTTLE_RATE_DUO_VERIFY', '6/minute'),
        'yubikey_otp_verify': config_get('THROTTLE_RATE_YUBIKEY_OTP_VERIFY', '6/minute'),
        'registration': config_get('THROTTLE_RATE_REGISTRATION', '20/day'),
        'user_delete': config_get('THROTTLE_RATE_USER_DELETE', '20/day'),
        'user_update': config_get('THROTTLE_RATE_USER_UPDATE', '20/day'),
        'fileserver_alive': config_get('THROTTLE_RATE_FILESERVER_ALIVE', '61/minute'),
        'fileserver_upload': config_get('THROTTLE_RATE_FILESERVER_UPLOAD', '10000/minute'),
        'fileserver_download': config_get('THROTTLE_RATE_RATE_FILESERVER_DOWNLOAD', '10000/minute'),
    },
    'NUM_PROXIES': NUM_PROXIES
}


LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'restapi_query_formatter': {
            '()': 'restapi.log.QueryFormatter',
            'format': '%(time_utc)s logger=%(name)s, %(message)s'
        }
    },
    'filters': {
        'restapi_query_console': {
            '()': 'restapi.log.FilterQueryConsole',
        },
    },
    'handlers': {
        'restapi_query_handler_console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'restapi_query_formatter',
            'filters': ['restapi_query_console'],
        },
    },
    'loggers': {
        'django.db.backends': {
            'level': 'DEBUG',
            'handlers': ['restapi_query_handler_console'],
        }
    }
}


for key, value in config_get('DEFAULT_THROTTLE_RATES', {}).items():
    REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'][key] = value # type: ignore

ROOT_URLCONF = 'psono.urls'
SITE_ID = 1

CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_METHODS = (
        'GET',
        'POST',
        'PUT',
        'PATCH',
        'DELETE',
        'OPTIONS'
    )

CORS_ALLOW_HEADERS = default_headers + (
    'audit-log',
    'authorization-validator',
    'pragma',
    'if-modified-since',
    'cache-control',
)

TEMPLATES = config_get('TEMPLATES', [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [HOME + '/psono/templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
])

WSGI_APPLICATION = 'wsgi.application'

# Database
DATABASE_URL = config_get('DATABASE_URL', None)
if DATABASE_URL:
    DATABASES = {
        'default': dj_database_url.config(env='PSONO_DATABASE_URL'),
    }
    DATABASE_SLAVE_URL = config_get('DATABASE_SLAVE_URL', None)
    if DATABASE_SLAVE_URL:
        DATABASES['slave'] = dj_database_url.config(env='PSONO_DATABASE_SLAVE_URL')
else:
    DATABASES = config_get('DATABASES', {
        'default': {
            'ENGINE': 'django.db.backends.postgresql_psycopg2', # django_postgrespool2
            'NAME': 'YourPostgresDatabase',
            'USER': 'YourPostgresUser',
            'PASSWORD': 'YourPostgresPassword',
            'HOST': 'YourPostgresHost',
            'PORT': 'YourPostgresPort',
        }
    })

for db_name, db_values in DATABASES.items():
    for db_configname, db_value in db_values.items():
        DATABASES[db_name][db_configname] = config_get('DATABASES_' + db_name.upper() + '_' + db_configname.upper(), DATABASES[db_name][db_configname])

DATABASE_POOL_ARGS = {
    'max_overflow': int(config_get('DATABASE_POOL_ARGS_MAX_OVERFLOW', 15)),
    'pool_size': int(config_get('DATABASE_POOL_ARGS_POOL_SIZE', 5)),
    'recycle': int(config_get('DATABASE_POOL_ARGS_RECYLCE', 300))
}

DISABLE_EMAIL_NEW_SHARE_CREATED = str(config_get('DISABLE_EMAIL_NEW_SHARE_CREATED', False)).lower() == 'true'
DISABLE_EMAIL_NEW_GROUP_MEMBERSHIP_CREATED = str(config_get('DISABLE_EMAIL_NEW_GROUP_MEMBERSHIP_CREATED', False)).lower() == 'true'


EMAIL_FROM = config_get('EMAIL_FROM')
EMAIL_HOST = config_get('EMAIL_HOST', 'localhost')
EMAIL_HOST_USER = config_get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = config_get('EMAIL_HOST_PASSWORD', '')
EMAIL_PORT = int(config_get('EMAIL_PORT', 25))
EMAIL_SUBJECT_PREFIX = config_get('EMAIL_SUBJECT_PREFIX', '')
EMAIL_USE_TLS = str(config_get('EMAIL_USE_TLS', False)).lower() == 'true'
EMAIL_USE_SSL = str(config_get('EMAIL_USE_SSL', False)).lower() == 'true'
EMAIL_SSL_CERTFILE = config_get('EMAIL_SSL_CERTFILE', None)
EMAIL_SSL_KEYFILE = config_get('EMAIL_SSL_KEYFILE', None)
EMAIL_TIMEOUT = int(config_get('EMAIL_TIMEOUT', 0)) if config_get('EMAIL_TIMEOUT', 0) else None

TOTP_VALID_WINDOW = int(config_get('TOTP_VALID_WINDOW', 0))
YUBIKEY_CLIENT_ID = config_get('YUBIKEY_CLIENT_ID', None)
YUBIKEY_SECRET_KEY = config_get('YUBIKEY_SECRET_KEY', None)
YUBICO_API_URLS = config_get('YUBICO_API_URLS', DEFAULT_YUBICO_API_URLS)
if isinstance(YUBICO_API_URLS, str) and YUBICO_API_URLS:
    YUBICO_API_URLS = [yubico_api_url.strip() for yubico_api_url in YUBICO_API_URLS.split(',')]

EMAIL_BACKEND = config_get('EMAIL_BACKEND', 'django.core.mail.backends.smtp.EmailBackend')

EMAIL_TEMPLATE_NEW_ENTRY_SHARED_SUBJECT = config_get('EMAIL_TEMPLATE_NEW_ENTRY_SHARED_SUBJECT', 'New entry shared')
EMAIL_TEMPLATE_NEW_GROUP_MEMBERSHIP_SUBJECT = config_get('EMAIL_TEMPLATE_NEW_GROUP_MEMBERSHIP_SUBJECT', 'New group invitation')
EMAIL_TEMPLATE_EMERGENCY_CODE_ARMED_SUBJECT = config_get('EMAIL_TEMPLATE_EMERGENCY_CODE_ARMED_SUBJECT', 'Emergency code armed')
EMAIL_TEMPLATE_REGISTRATION_SUCCESSFUL_SUBJECT = config_get('EMAIL_TEMPLATE_REGISTRATION_SUCCESSFUL_SUBJECT', 'Registration successful')

ANYMAIL = {
    "MAILGUN_API_URL": config_get('MAILGUN_API_URL', 'https://api.mailgun.net/v3'),  # For EU: https://api.eu.mailgun.net/v3
    "MAILGUN_API_KEY": config_get('MAILGUN_ACCESS_KEY', ''),
    "MAILGUN_SENDER_DOMAIN": config_get('MAILGUN_SERVER_NAME', ''),

    "MAILJET_API_KEY": config_get('MAILJET_API_KEY', ''),
    "MAILJET_SECRET_KEY": config_get('MAILJET_SECRET_KEY', ''),
    "MAILJET_API_URL": config_get('MAILJET_API_URL', 'https://api.mailjet.com/v3'),

    "MANDRILL_API_KEY": config_get('MANDRILL_API_KEY', ''),
    "MANDRILL_API_URL": config_get('MANDRILL_API_URL', 'https://mandrillapp.com/api/1.0'),

    "POSTMARK_SERVER_TOKEN": config_get('POSTMARK_SERVER_TOKEN', ''),
    "POSTMARK_API_URL": config_get('POSTMARK_API_URL', 'https://api.postmarkapp.com/'),

    "SENDGRID_API_KEY": config_get('SENDGRID_API_KEY', ''),
    "SENDGRID_API_URL": config_get('SENDGRID_API_URL', 'https://api.sendgrid.com/v3/'),

    "SENDINBLUE_API_KEY": config_get('SENDINBLUE_API_KEY', ''),
    "SENDINBLUE_API_URL": config_get('SENDINBLUE_API_URL', 'https://api.sendinblue.com/v3/'),

    "SPARKPOST_API_KEY": config_get('SPARKPOST_API_KEY', ''),
    "SPARKPOST_API_URL": config_get('SPARKPOST_API_URL', 'https://api.sparkpost.com/api/v1'),  # For EU: https://api.eu.sparkpost.com/api/v1

    "IGNORE_UNSUPPORTED_FEATURES": str(config_get('IGNORE_UNSUPPORTED_FEATURES', False)).lower() == 'true',

    "AMAZON_SES_CLIENT_PARAMS": {
        "aws_access_key_id": config_get('AMAZON_SES_CLIENT_PARAMS_ACCESS_KEY_ID', ''),
        "aws_secret_access_key": config_get('AMAZON_SES_CLIENT_PARAMS_SECRET_ACCESS_KEY', ''),
        "region_name": config_get('AMAZON_SES_CLIENT_PARAMS_REGION_NAME', "us-west-2"),
    },
}

DEFAULT_FROM_EMAIL = config_get('EMAIL_FROM')

HEALTHCHECK_TIME_SYNC_ENABLED = str(config_get('HEALTHCHECK_TIME_SYNC_ENABLED', True)).lower() == 'true'

CACHE_ENABLE = str(config_get('CACHE_ENABLE', False)).lower() == 'true'

if str(config_get('CACHE_DB', False)).lower() == 'true':
    CACHES = {
        "default": {
            "BACKEND": 'django.core.cache.backends.db.DatabaseCache',
            "LOCATION": 'restapi_cache',
            "KEY_PREFIX": f'{PUBLIC_KEY}:{VERSION}'.replace(" ", "_"),
        }
    }

if str(config_get('CACHE_REDIS', False)).lower() == 'true':
    CACHES = {
        "default": { # type: ignore
            "BACKEND": "django_redis.cache.RedisCache",
            "LOCATION": config_get('CACHE_REDIS_LOCATION', 'redis://localhost:6379/0'),
            "KEY_PREFIX": f'{PUBLIC_KEY}:{VERSION}'.replace(" ", "_"),
            "OPTIONS": { # type: ignore
                "CLIENT_CLASS": "django_redis.client.DefaultClient",
            }
        }
    }

if not str(config_get('THROTTLING', True)).lower() == 'true':
    CACHES = {
        "default": {
            "BACKEND": 'django.core.cache.backends.dummy.DummyCache',
            "KEY_PREFIX": f'{PUBLIC_KEY}:{VERSION}'.replace(" ", "_"),
        }
    }

DISABLE_LAST_PASSWORDS = int(config_get('DISABLE_LAST_PASSWORDS', 0))

MANAGEMENT_ENABLED = str(config_get('MANAGEMENT_ENABLED', False)).lower() == 'true'
FILESERVER_HANDLER_ENABLED = str(config_get('FILESERVER_HANDLER_ENABLED', True)).lower() == 'true'
CREDIT_HANDLER_ENABLED = str(config_get('CREDIT_HANDLER_ENABLED', True)).lower() == 'true'
FILES_ENABLED = str(config_get('FILES_ENABLED', True)).lower() == 'true'

FILE_REPOSITORY_TYPES = [
    'azure_blob',
    'gcp_cloud_storage',
    'aws_s3',
    'do_spaces',
    'backblaze',
    'other_s3',
]

FILESERVER_ALIVE_TIMEOUT = int(config_get('FILESERVER_ALIVE_TIMEOUT', 30))
AUTH_KEY_LENGTH_BYTES = int(config_get('AUTH_KEY_LENGTH_BYTES', 64))
USER_PRIVATE_KEY_LENGTH_BYTES = int(config_get('USER_PRIVATE_KEY_LENGTH_BYTES', 80))
USER_PUBLIC_KEY_LENGTH_BYTES = int(config_get('USER_PUBLIC_KEY_LENGTH_BYTES', 32))
USER_SECRET_KEY_LENGTH_BYTES = int(config_get('USER_SECRET_KEY_LENGTH_BYTES', 80))
NONCE_LENGTH_BYTES = int(config_get('NONCE_LENGTH_BYTES', 24))
ACTIVATION_LINK_SECRET = config_get('ACTIVATION_LINK_SECRET')
WEB_CLIENT_URL = config_get('WEB_CLIENT_URL', '')
DB_SECRET = config_get('DB_SECRET')
EMAIL_SECRET_SALT = config_get('EMAIL_SECRET_SALT')

ACTIVATION_LINK_TIME_VALID = int(config_get('ACTIVATION_LINK_TIME_VALID', 2592000)) # in seconds
DEFAULT_TOKEN_TIME_VALID = int(config_get('DEFAULT_TOKEN_TIME_VALID', 86400)) # 24h in seconds
MAX_WEB_TOKEN_TIME_VALID = int(config_get('MAX_WEB_TOKEN_TIME_VALID', 2592000)) # 30d in seconds
MAX_APP_TOKEN_TIME_VALID = int(config_get('MAX_APP_TOKEN_TIME_VALID', 31536000)) # 365d in seconds
MAX_API_KEY_TOKEN_TIME_VALID = int(config_get('MAX_API_KEY_TOKEN_TIME_VALID', 600)) # 10 min in seconds
RECOVERY_VERIFIER_TIME_VALID = int(config_get('RECOVERY_VERIFIER_TIME_VALID', 600)) # in seconds
REPLAY_PROTECTION_DISABLED = str(config_get('REPLAY_PROTECTION_DISABLED', False)).lower() == 'true' # disables the replay protection
DEVICE_PROTECTION_DISABLED = str(config_get('DEVICE_PROTECTION_DISABLED', False)).lower() == 'true' # disables the device fingerprint protection
REPLAY_PROTECTION_TIME_DFFERENCE = int(config_get('REPLAY_PROTECTION_TIME_DFFERENCE', 20)) # in seconds
DISABLE_CENTRAL_SECURITY_REPORTS = str(config_get('DISABLE_CENTRAL_SECURITY_REPORTS', False)).lower() == 'true' # disables central security reports

DISABLE_CALLBACKS = str(config_get('DISABLE_CALLBACKS', True)).lower() == 'true' # disables callbacks
ALLOWED_CALLBACK_URL_PREFIX = config_get('ALLOWED_CALLBACK_URL_PREFIX', ['*'])

if isinstance(ALLOWED_CALLBACK_URL_PREFIX, str):
    ALLOWED_CALLBACK_URL_PREFIX = [allowed_callback_prefix.strip() for allowed_callback_prefix in ALLOWED_CALLBACK_URL_PREFIX.split(',')]

ALLOW_MULTIPLE_SESSIONS = str(config_get('ALLOW_MULTIPLE_SESSIONS', True)).lower() == 'true' # Allows multiple sessions for each user
AUTO_PROLONGATION_TOKEN_TIME_VALID = int(config_get('AUTO_PROLONGATION_TOKEN_TIME_VALID', 0)) #  in seconds, 900 = 15 mins, 0 disables it

AUTO_PROLONGATION_URL_EXCEPTIONS = [
    '/user/status/',
]

SECURE_PROXY_SSL_HEADER = config_get('SECURE_PROXY_SSL_HEADER', None)


# Credit costs
SHARD_CREDIT_BUY_ADDRESS = config_get('SHARD_CREDIT_BUY_ADDRESS', 'https://example.com')
SHARD_CREDIT_DEFAULT_NEW_USER = Decimal(str(config_get('SHARD_CREDIT_DEFAULT_NEW_USER', 0))) # the default credits in Euro for new users
SHARD_CREDIT_COSTS_UPLOAD = Decimal(str(config_get('SHARD_CREDIT_COSTS_UPLOAD', 0))) # costs in Euro for an upload of 1 GB
SHARD_CREDIT_COSTS_DOWNLOAD = Decimal(str(config_get('SHARD_CREDIT_COSTS_DOWNLOAD', 0))) # costs in Euro for a download of 1 GB
SHARD_CREDIT_COSTS_STORAGE = Decimal(str(config_get('SHARD_CREDIT_COSTS_STORAGE', 0))) # costs in Euro for the storage of 1 GB per day

# DEFAULT_FILE_REPOSITORY_ENABLED = str(config_get('DEFAULT_FILE_REPOSITORY_ENABLED', False)).lower() == 'true'
# DEFAULT_FILE_REPOSITORY_UUID = config_get('DEFAULT_FILE_REPOSITORY_ENABLED', '00000000-0000-0000-0000-000000000000') # Don't change this as you might lose access to data
# DEFAULT_FILE_REPOSITORY_TITLE = config_get('DEFAULT_FILE_REPOSITORY_TITLE', 'Default Repository')
# DEFAULT_FILE_REPOSITORY_BUCKET = config_get('DEFAULT_FILE_REPOSITORY_BUCKET', None)
# DEFAULT_FILE_REPOSITORY_TYPE = config_get('DEFAULT_FILE_REPOSITORY_TYPE', 'gcp_cloud_storage')
# DEFAULT_FILE_REPOSITORY_CREDENTIALS = config_get('DEFAULT_FILE_REPOSITORY_CREDENTIALS', None)
# # Read path to config with defaults for environment specific variables
# DEFAULT_FILE_REPOSITORY_CREDENTIAL_PATH = None
#
# if DEFAULT_FILE_REPOSITORY_TYPE == 'gcp_cloud_storage':
#     DEFAULT_FILE_REPOSITORY_CREDENTIAL_PATH = os.environ.get('GOOGLE_APPLICATION_CREDENTIALS', None)
#
# DEFAULT_FILE_REPOSITORY_CREDENTIAL_PATH = config_get('DEFAULT_FILE_REPOSITORY_CREDENTIAL_PATH', DEFAULT_FILE_REPOSITORY_CREDENTIAL_PATH)

DATABASE_ROUTERS = ['restapi.database_router.MainRouter']

TIME_SERVER = config_get('TIME_SERVER', 'time.google.com')

# Internationalization
# https://docs.djangoproject.com/en/1.8/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

AUTHENTICATION_METHODS = config_get('AUTHENTICATION_METHODS', ['AUTHKEY'])
if isinstance(AUTHENTICATION_METHODS, str) and AUTHENTICATION_METHODS:
    AUTHENTICATION_METHODS = [authentication_method.strip() for authentication_method in AUTHENTICATION_METHODS.split(',')]
elif isinstance(AUTHENTICATION_METHODS, str):
    AUTHENTICATION_METHODS = []

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.8/howto/static-files/
STATIC_ROOT = os.path.join(BASE_DIR, "static/")
STATIC_URL = '/static/'

HOSTNAME = socket.getfqdn()

with open(os.path.join(BASE_DIR, 'SHA.txt')) as f:
    SHA = f.readline().rstrip()

# Add Sentry logging
SENTRY_DSN = config_get('SENTRY_DSN', '')
if SENTRY_DSN:
    RAVEN_CONFIG = {
        'dsn': SENTRY_DSN,
        'environment': config_get('SENTRY_ENVIRONMENT', 'development'),
        'release': VERSION,
        'site': PUBLIC_KEY,
    }
    INSTALLED_APPS.append('raven.contrib.django.raven_compat')

def generate_signature():

    if WEB_CLIENT_URL:
        web_client = WEB_CLIENT_URL
    else:
        url = urlparse(HOST_URL)
        web_client = url.scheme + '://' + url.netloc

    info = {
        'version': VERSION,
        'api': 1,
        'log_audit': False,
        'public_key': PUBLIC_KEY,
        'authentication_methods': AUTHENTICATION_METHODS,
        'web_client': web_client,
        'management': MANAGEMENT_ENABLED,
        'files': FILES_ENABLED,
        'auto_prolongation_token_time_valid': AUTO_PROLONGATION_TOKEN_TIME_VALID,
        'allowed_second_factors': ALLOWED_SECOND_FACTORS,
        'disable_central_security_reports': DISABLE_CENTRAL_SECURITY_REPORTS,
        'disable_callbacks': DISABLE_CALLBACKS,
        'allow_user_search_by_email': ALLOW_USER_SEARCH_BY_EMAIL,
        'allow_user_search_by_username_partial': ALLOW_USER_SEARCH_BY_USERNAME_PARTIAL,
        'system_wide_duo_exists': DUO_SECRET_KEY != '',  #nosec -- not [B105:hardcoded_password_string]
        'multifactor_enabled': MULTIFACTOR_ENABLED,
        'type': 'CE',
        'credit_buy_address': SHARD_CREDIT_BUY_ADDRESS,
        'credit_costs_upload': str(SHARD_CREDIT_COSTS_UPLOAD),
        'credit_costs_download': str(SHARD_CREDIT_COSTS_DOWNLOAD),
        'credit_costs_storage': str(SHARD_CREDIT_COSTS_STORAGE),
    }

    info = json.dumps(info)

    signing_box = nacl.signing.SigningKey(PRIVATE_KEY, encoder=nacl.encoding.HexEncoder)
    verify_key = signing_box.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    # The first 128 chars (512 bits or 64 bytes) are the actual signature, the rest the binary encoded info
    signature = binascii.hexlify(signing_box.sign(info.encode()))[:128]

    return {
        'info': info,
        'signature': signature,
        'verify_key': verify_key,
    }

SIGNATURE = generate_signature()
