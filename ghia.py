from collections import deque
from itertools import chain
import configparser
import re

import click
import requests


valid_reposlug = re.compile('^[^/]+/[^/]+$')
next_link = re.compile('<([^>]*)>; ?rel=.next')


class IssuesIterator:
    def __init__(self, repo, session):
        self.session = session
        self.next = repo['issues_url'].format_map({'/number': ''})
        self.parsed = deque()

    def __iter__(self):
        return self

    def __next__(self):
        if not self.parsed:
            if not self.next:
                raise StopIteration

            r = self.session.get(self.next)
            self.parsed = deque(r.json())
            nexts = None
            if 'Link' in r.headers:
                nexts = next_link.findall(r.headers['Link'])

            if not nexts:
                next = None
            else:
                next = nexts[0]
            self.next = next

        return self.parsed.popleft()


def get_issues(repo, session):
    return IssuesIterator(repo, session)


def get_labels(issue):
    return map(lambda label: label['name'], issue['labels'])


def issue_new_assignment(issue, config):
    users = set()

    # Assign according to title
    for user in config['rules']:
        for regex in chain(user['rules']['title'], user['rules']['any']):
            if regex.search(issue['title']):
                users.add(user['name'])
                break

    # Assign according to text
    for user in config['rules']:
        for regex in chain(user['rules']['text'], user['rules']['any']):
            if regex.search(issue['body']):
                users.add(user['name'])
                break

    # Assign according to labels
    for label in get_labels(issue):
        for user in config['rules']:
            for regex in chain(user['rules']['label'], user['rules']['any']):
                if regex.search(label):
                    users.add(user['name'])
                    break

    return users


def issue_current_assignment(issue):
    return set(map(lambda assignee: assignee['login'], issue['assignees']))


def session_init(token):
    session = requests.Session()
    session.headers['Authorization'] = f'token {token}'
    session.headers['Accept'] = 'application/vnd.github.v3+json'

    return session


def get_repo(session, reposlug):
    r = session.get(f'https://api.github.com/repos/{reposlug}')
    if r.status_code != 200:
        raise IOError

    return r.json()


def validate_reposlug(ctx, param, value):
    if not valid_reposlug.match(value):
        raise click.BadParameter('not in owner/repository format')
    return value


def parse_auth(ctx, param, value):
    error_text = 'incorrect configuration format'
    auth = configparser.ConfigParser()
    try:
        auth.read_file(value)
    except:
        raise click.BadParameter(error_text)

    if not 'github' in auth or not 'token' in auth['github']:
        raise click.BadParameter(error_text)

    return auth['github']['token']


def parse_rules(ctx, param, value):
    error_text = 'incorrect configuration format'
    rules = configparser.ConfigParser()
    rules.optionxform=str
    try:
        rules.read_file(value)
    except:
        raise click.BadParameter(error_text)

    rules.read_file(value)

    if not 'patterns' in rules:
        raise click.BadParameter(error_text)

    fallback = None
    if 'fallback' in rules:
        if not 'label' in rules['fallback']:
            raise click.BadParameter(error_text)

        fallback = rules['fallback']['label']

    parsed_rules = []
    for name in rules['patterns']:
        parsed_rule = {
            'name': name,
            'rules': {
                'title': [],
                'text': [],
                'label': [],
                'any': [],
            }
        }

        # Filter out empty lines and split the rest to tag and pattern
        lines = map(
            lambda line: line.split(':', 1), filter(
                lambda line: line != '',
                rules['patterns'][name].split('\n')
        ))

        for line in lines:
            if not line[0] in parsed_rule['rules']:
                raise click.BadParameter(error_text)

            try:
                regex = re.compile(line[1], flags=re.IGNORECASE)
            except:
                raise click.BadParameter(error_text)

            parsed_rule['rules'][line[0]].append(regex)

        parsed_rules.append(parsed_rule)

    return {'fallback': fallback, 'rules': parsed_rules}


@click.command()
@click.option('-s', '--strategy',
    type=click.Choice(['append', 'set', 'change']), default='append',
    show_default=True, help='How to handle assignment collisions.')
@click.option('-d', '--dry-run', is_flag=True,
    help='Run without making any changes.')
@click.option('-a', '--config-auth', type=click.File('r'), required=True,
    callback=parse_auth, help='File with authorization configuration.')
@click.option('-r', '--config-rules', type=click.File('r'), required=True,
    callback=parse_rules, help='File with assignment rules configuration.')
@click.argument('reposlug', callback=validate_reposlug)
def run(strategy, dry_run, config_auth, config_rules, reposlug):
    """CLI tool for automatic issue assigning of GitHub issues"""
    pass

if __name__ == '__main__':
    run()