"""
Usage:
  aws-keys add <NAME>
  aws-keys rm <NAME>
  aws-keys sync [NAME] [--stdin]
  aws-keys env [NAME]

Options:
  -h --help     Show this screen.

"""
from collections import namedtuple
from getpass import getpass
import sys
import time
import datetime
import dateutil.parser

from docopt import docopt
import pytz
import dateutil.parser
import keyring

SESSION_DURATION = 60 * 60

_CredentialInfo = namedtuple('CredentialInfo', ['seconds_left', 'aws_env'])


def log(msg):
    print('aws-keys: {}'.format(msg), file=sys.stderr)


def make_aws_env(access_key_id, secret_access_key, session_token=None):
    aws_env = {
        'AWS_ACCESS_KEY': access_key_id,
        'AWS_ACCESS_KEY_ID': access_key_id,
        'AWS_SECRET_ACCESS_KEY': secret_access_key,
        'AWS_SECRET_KEY': secret_access_key,
    }
    if session_token:
        aws_env['AWS_SESSION_TOKEN'] = session_token

    return aws_env


def make_exports(aws_env):
    lines = ['export {}={}'.format(*kv) for kv in sorted(aws_env.items())]
    return '\n'.join(lines)


class Credentials(object):
    def __init__(self, name='', access_key_id='', secret_access_key='',
                 mfa_serial='', temporary_credentials=None):
        self.name = name
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.mfa_serial = mfa_serial
        self.temporary_credentials = temporary_credentials

    def are_valid(self):
        """
        Return whether the credentials are valid for the given duration.
        """
        return (self.temporary_credentials and
                self.temporary_credentials.time_until_expiration() > 0)


class TemporaryCredentials(object):
    def __init__(self,  temporary_access_key='', temporary_secret_key='',
                 session_token='', expiration=''):
        self.temporary_access_key = temporary_access_key
        self.temporary_secret_key = temporary_secret_key
        self.session_token = session_token
        self.expiration = expiration

    def time_until_expiration(self):
        return (dateutil.parser.parse(self.expiration) - datetime.datetime.now(pytz.timezone('UTC'))).total_seconds()

    def to_aws_env(self):
        return make_aws_env(self.temporary_access_key, self.temporary_secret_key,
                    session_token=self.session_token)

    def __str__(self):
        return "%s %s %s %s" % (
            self.temporary_access_key,
            self.temporary_secret_key,
            self.session_token,
            self.expiration,
        )


def main():
    arguments = docopt(__doc__)
    if arguments['add']:
        add(arguments['<NAME>'])
    elif arguments['rm']:
        rm(arguments['<NAME>'])
    elif arguments['env']:
        env(arguments['NAME'])
    elif arguments['sync']:
        sync(arguments['NAME'], from_stdin=arguments.get('--stdin'))


def add(name=None):
    if not name:
        name = input("Name for the AWS credentials (e.g. 'bob'): ").strip()
    access_key_id = input("Access Key ID: ").strip()
    secret_access_key = input("Secret Access Key: ").strip()
    enable_mfa = input("Use MFA on this account? (yes/no): ").strip().lower()
    if enable_mfa.startswith('y'):
        mfa_serial = input("Your MFA device serial (arn:aws:..) ID: ").strip()
    make_default = input("Make this account the default for aws-keys? (yes/no): ").strip().lower()

    if make_default.startswith('y'):
        make_default = True
    else:
        make_default = False

    keyring.set_password('aws-keyring-access-key-id', name, access_key_id)
    keyring.set_password('aws-keyring-secret-access-key', name, secret_access_key)
    if enable_mfa.startswith('y'):
        keyring.set_password('aws-keyring-mfa', name, mfa_serial)
    if make_default:
        keyring.set_password('aws-keyring-default', 'default', name)

    log("Credentials added for account name '{}'.".format(name))


def rm(name):
    credentials = get_credentials(name)

    keyring.delete_password('aws-keyring-access-key-id', name)
    keyring.delete_password('aws-keyring-secret-access-key', name)

    if credentials.mfa_serial:
        keyring.delete_password('aws-keyring-mfa', name)

    log("Credentials for account name '{}' deleted.".format(name))


def env(name=None):
    credentials = get_credentials(name)

    if credentials.are_valid():
        # Unfortunately, we can't just call sync() here and get new credentials
        # if they're expired, because env() is designed to be added directly into
        # the shell environment and so we can't prompt for interactive input for
        # the MFA token. Instead, we tell people to first call sync() and then
        # use env().
        aws_env = credentials.temporary_credentials.to_aws_env()
    else:
        aws_env = make_aws_env(credentials.access_key_id, credentials.secret_access_key)

    environment_exports = make_exports(aws_env)
    print(environment_exports)


def update_keyring(name=None, from_stdin=False):
    import boto
    from boto.sts import STSConnection

    if name is None:
        name = get_default_name()

    mfa_TOTP = None

    if from_stdin:
        mfa_TOTP = ''.join(sys.stdin.readlines()).strip()

    if not mfa_TOTP:
        mfa_TOTP = getpass("Enter the MFA code: ")

    credentials = get_credentials(name)

    sts_connection = STSConnection(
        aws_access_key_id=credentials.access_key_id,
        aws_secret_access_key=credentials.secret_access_key
    )

    temporary_credentials = sts_connection.get_session_token(
        duration=SESSION_DURATION,
        mfa_serial_number=credentials.mfa_serial,
        mfa_token=mfa_TOTP,
    )

    details = TemporaryCredentials(
        temporary_access_key=temporary_credentials.access_key,
        temporary_secret_key=temporary_credentials.secret_key,
        session_token=temporary_credentials.session_token,
        expiration=temporary_credentials.expiration
    )

    keyring.set_password('aws-keyring-temporary-credentials', name, str(details))


# TODO: allow re-syncing even if the current credentials are still valid
#  (e.g. if they will expire in a few seconds).
def sync(name=None, from_stdin=False):
    if not name:
        name = get_default_name()

    credentials = get_credentials(name)
    if not credentials.mfa_serial:
        # Nothing to do here.
        return

    # Have temporary credentials and they aren't expired yet, so no need to
    # get new ones.
    if credentials.are_valid():
        return

    update_keyring(name=name, from_stdin=from_stdin)


def get_default_name():
    default = keyring.get_password('aws-keyring-default', 'default')
    return default


def get_credentials(name=None):
    if not name:
        name = get_default_name()

    access_key_id = keyring.get_password('aws-keyring-access-key-id', name)
    secret_access_key = keyring.get_password('aws-keyring-secret-access-key', name)
    mfa_serial = keyring.get_password('aws-keyring-mfa', name)
    temporary_credentials = keyring.get_password('aws-keyring-temporary-credentials', name)
    if temporary_credentials:
        access_key, secret_key, session_token, expiration = temporary_credentials.split()
        temporary_credentials = TemporaryCredentials(
            temporary_access_key=access_key,
            temporary_secret_key=secret_key,
            session_token=session_token,
            expiration=expiration
        )

    credentials = Credentials(
        name=name,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        mfa_serial=mfa_serial,
        temporary_credentials=temporary_credentials
    )
    return credentials


def fetch_aws_env(name=None):
    """
    Fetch AWS credentials from the keyring, and return environment variables.

    Returns: (seconds_left, aws_env)

      seconds_left: the remaining number of seconds that the environment
        variables are valid for.
      aws_env: a dict of the AWS environment variables, or an empty dict
        if there are no temporary credentials.
    """
    credentials = get_credentials(name)
    temp_credentials = credentials.temporary_credentials
    if not temp_credentials:
        return _CredentialInfo(seconds_left=-1, aws_env={})

    seconds_left = temp_credentials.time_until_expiration()
    aws_env = temp_credentials.to_aws_env()

    return _CredentialInfo(seconds_left=seconds_left, aws_env=aws_env)
