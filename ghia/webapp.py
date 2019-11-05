from .helpers import parse_rules_configparse, parse_auth_configparse, valid_types
from .github import session_init, get_user, assign_to_issue

from flask import Flask, Blueprint, current_app, request, render_template
import configparser
import hashlib
import hmac
import os


root_blueprint = Blueprint('root', __name__)


def create_app(conf=None):
    app = Flask(__name__)
    app.register_blueprint(root_blueprint)

    conf = configparser.ConfigParser()
    conf.optionxform=str
    conf.read(os.environ['GHIA_CONFIG'].split(':'))

    rules = parse_rules_configparse(conf)
    auth = parse_auth_configparse(conf)

    session = session_init(auth['token'])
    user = get_user(session)

    app.config['user'] = user
    app.config['rules'] = rules
    app.config['session'] = session
    app.config['secret'] = auth['secret']

    return app


@root_blueprint.route('/', methods=['GET', 'POST'])
def root():
    if request.method == 'GET':
        return render_template(
            'index.html',
            username=current_app.config['user']['login'],
            rules=current_app.config['rules'],
            valid_types=valid_types
        )

    if not 'X-GitHub-Event' in request.headers:
        return 'X-GitHub-Event header missing', 400

    if current_app.config['secret']:
        if not "X-Hub-Signature" in request.headers:
            return 'missing signature', 400

        signature = request.headers['X-Hub-Signature']

        hmac_gen = hmac.new(current_app.config['secret'].encode(), request.data,
            hashlib.sha1)
        digest = "sha1=" + hmac_gen.hexdigest()

        # Using compare_digest because using `==` would
        # make the app vulnerable to timing attacks.
        if not hmac.compare_digest(signature, digest):
            return 'invalid signature', 400

    if request.headers['X-GitHub-Event'] == 'ping':
        return ''

    if request.headers['X-GitHub-Event'] != 'issues':
        return 'unsupported event type', 400

    body = request.get_json()

    assign_to_issue(
        current_app.config['session'],
        body['issue'],
        body['repository']['full_name'],
        'append',
        current_app.config['rules'],
        False
    )

    return f"{body['issue']['url']}\n{body['repository']['full_name']}\n"
