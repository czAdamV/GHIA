from collections import deque
from itertools import chain
import configparser
import re

import click
import requests


valid_reposlug = re.compile('^[^/]+/[^/]+$')


class IssuesListException(Exception):
    pass


class IssuesIterator:
    def __init__(self, reposlug, session):
        self.session = session
        self.next = f'https://api.github.com/repos/{reposlug}/issues'
        self.parsed = deque()

    def __iter__(self):
        return self

    def __next__(self):
        if not self.parsed:
            if not self.next:
                raise StopIteration

            r = self.session.get(self.next)
            if r.status_code != 200:
                raise IssuesListException
            self.parsed = deque(r.json())
            self.next = r.links['next']['url'] if 'next' in r.links else None

        return self.parsed.popleft()


def get_issues(reposlug, session):
    return IssuesIterator(reposlug, session)


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


def add_label(session, issue, label):
    r = session.post(f"{issue['url']}/labels", json={'labels': [label]})

    if r.status_code != 200:
        raise Exception


def set_asignees(session, issue, add, remove):
    if add['assignees']:
        r = session.post(f"{issue['url']}/assignees", json=add)
        if r.status_code != 201:
            raise Exception

    if remove['assignees']:
        r = session.delete(f"{issue['url']}/assignees", json=remove)
        if r.status_code != 200:
            raise Exception


def print_diff(new, old):
    for user in sorted(new | old, key=str.casefold):
        if user not in new:
            click.echo(f'   {click.style("-", bold=True, fg="red")} {user}')

        elif user not in old:
            click.echo(f'   {click.style("+", bold=True, fg="green")} {user}')

        else:
            click.echo(f'   {click.style("=", bold=True, fg="blue")} {user}')


def assign_to_issue(session, issue, reposlug, strategy, config_rules, dry_run):
    number = issue['number']
    html_url = issue['html_url']

    click.echo(
        f"-> {click.style(f'{reposlug}#{number}', bold=True)} ({html_url})"
    )

    old = issue_current_assignment(issue)
    new = issue_new_assignment(issue, config_rules)

    if old and strategy == 'set':
        print_diff(old, old)
        return

    if strategy == 'append':
        new |= old

    if not new and config_rules["fallback"]:
        if config_rules['fallback'] in get_labels(issue):
            click.echo('   ', nl=False)
            click.secho('FALLBACK', bold=True, fg='yellow', nl=False)
            click.echo(f': already has label "{config_rules["fallback"]}"')

        else:
            if not dry_run:
                try:
                    add_label(session, issue, config_rules["fallback"])
                except:
                    click.echo('   ', nl=False, err=True)
                    click.secho('ERROR', fg='red', bold=True, nl=False,
                        err=True)
                    click.echo(f': Could not update issue {reposlug}#{number}',
                        err=True)
                    return

            click.echo('   ', nl=False)
            click.secho('FALLBACK', bold=True, fg='yellow', nl=False)
            click.echo(f': added label "{config_rules["fallback"]}"')

    add = {'assignees': list(new - old)}
    remove = {'assignees': list(old - new)}
    try:
        if not dry_run:
            set_asignees(session, issue, add, remove)

    except:
        click.echo('   ', nl=False, err=True)
        click.secho('ERROR', fg='red', bold=True, nl=False, err=True)
        click.echo(f': Could not update issue {reposlug}#{number}', err=True)
        return

    print_diff(new, old)


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

    session = session_init(config_auth)

    try:
        for issue in get_issues(reposlug, session):
            assign_to_issue(session, issue, reposlug, strategy, config_rules,
                dry_run)
    except IssuesListException as e:
        click.secho('ERROR', fg='red', bold=True, nl=False, err=True)
        click.echo(f': Could not list issues for repository {reposlug}',
            err=True)
        exit(10)


if __name__ == '__main__':
    run()