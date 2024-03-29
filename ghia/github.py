from .helpers import print_diff


from collections import deque
from itertools import chain
import contextlib
import requests
import aiohttp
import click


class IssuesListException(Exception):
    pass


class IssuesIterator:
    def __init__(self, reposlug, session):
        self.session = session
        self.next = f'https://api.github.com/repos/{reposlug}/issues'
        self.next_promise = None
        self.parsed = deque()

    def __iter__(self):
        return self

    def __aiter__(self):
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

    async def __anext__(self):
        if not self.parsed:
            if not self.next:
                raise StopAsyncIteration

            if not self.next_promise:
                self.next_promise = self.session.get(self.next)

            r = await self.next_promise
            if r.status != 200:
                raise IssuesListException

            self.next = r.links['next']['url'] if 'next' in r.links else None

            if self.next:
                self.next_promise = self.session.get(self.next)

            self.parsed = deque(await r.json())

        return self.parsed.popleft()


def get_issues(reposlug, session):
    return IssuesIterator(reposlug, session)


def get_issues_async(reposlug, session):
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


@contextlib.asynccontextmanager
async def session_init_aiohttp(token):
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    async with aiohttp.ClientSession(headers=headers) as session:
        yield session


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

    output = ""
    error = ""

    output += f"-> {click.style(f'{reposlug}#{number}', bold=True)} ({html_url})\n"

    old = issue_current_assignment(issue)
    new = issue_new_assignment(issue, config_rules)

    if old and strategy == 'set':
        output += print_diff(old, old)

        if output: click.echo(output, nl=False)
        if error: click.echo(error, err=True, nl=False)

        return

    if strategy == 'append':
        new |= old

    if not new and config_rules["fallback"]:
        if config_rules['fallback'] in get_labels(issue):
            output += '   '
            output += click.style('FALLBACK', bold=True, fg='yellow')
            output += f': already has label "{config_rules["fallback"]}"\n'

        else:
            if not dry_run:
                try:
                    add_label(session, issue, config_rules["fallback"])
                except:
                    error += '   '
                    error += click.style('ERROR', bold=True, fg='red')
                    error += f': Could not update issue {reposlug}#{number}\n'

                    if output: click.echo(output, nl=False)
                    if error: click.echo(error, err=True, nl=False)

                    return

            output += '   '
            output += click.style('FALLBACK', bold=True, fg='yellow')
            output += f': added label "{config_rules["fallback"]}"\n'

    add = {'assignees': list(new - old)}
    remove = {'assignees': list(old - new)}
    try:
        if not dry_run:
            set_asignees(session, issue, add, remove)

    except:
        error += '   '
        error += click.style('ERROR', bold=True, fg='red')
        error += f': Could not update issue {reposlug}#{number}\n'

        if output: click.echo(output, nl=False)
        if error: click.echo(error, err=True, nl=False)

        return

    output += print_diff(new, old)

    if output: click.echo(output, nl=False)
    if error: click.echo(error, err=True, nl=False)
