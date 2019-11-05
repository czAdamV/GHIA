from .helpers import parse_auth, parse_rules, valid_types
from .github import session_init, get_issues, assign_to_issue, IssuesListException

import click
import re


valid_reposlug = re.compile('^[^/]+/[^/]+$')


def validate_reposlug(ctx, param, value):
    if not valid_reposlug.match(value):
        raise click.BadParameter('not in owner/repository format')
    return value


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

    session = session_init(config_auth['token'])

    try:
        for issue in get_issues(reposlug, session):
            assign_to_issue(session, issue, reposlug, strategy, config_rules,
                dry_run)
    except IssuesListException as e:
        click.secho('ERROR', fg='red', bold=True, nl=False, err=True)
        click.echo(f': Could not list issues for repository {reposlug}',
            err=True)
        exit(10)


def main():
    run(prog_name='ghia')