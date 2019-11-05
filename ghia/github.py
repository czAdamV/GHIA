from .helpers import print_diff


from collections import deque
from itertools import chain
import requests
import click


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


def get_user(session):
    r = session.get('https://api.github.com/user')
    return r.json()


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


def assign_to_issue(session, issue, reposlug, strategy, config_rules, dry_run):
    if issue['state'] != 'open':
        return

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
