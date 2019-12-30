from .helpers import parse_auth, parse_rules, valid_types
from .github import session_init, session_init_aiohttp, get_issues, \
                    get_issues_async, assign_to_issue, IssuesListException

from functools import partial

import aiohttp
import asyncio
import click
import re


valid_reposlug = re.compile('^[^/]+/[^/]+$')


def validate_reposlug(ctx, param, value):
    for reposlug in value:
        if not valid_reposlug.match(reposlug):
            raise click.BadParameter('not in owner/repository format')

    return value


def process_all(reposlugs, config_auth, config_rules, strategy, dry_run):
    session = session_init(config_auth['token'])

    try:
        for reposlug in reposlugs:
            for issue in get_issues(reposlug, session):
                assign_to_issue(session, issue, reposlug, strategy, config_rules,
                    dry_run)
    except IssuesListException as e:
        click.secho('ERROR', fg='red', bold=True, nl=False, err=True)
        click.echo(f': Could not list issues for repository {reposlug}',
            err=True)
        exit(10)


async def process_all_async(reposlugs, config_auth, config_rules, strategy, dry_run):
    try:
        tasks = []
        loop = asyncio.get_running_loop()

        async with session_init_aiohttp(config_auth['token']) as aio_session:
            session = session_init(config_auth['token'])
            for reposlug in reposlugs:
                async for issue in get_issues_async(reposlug, aio_session):
                    func = partial(assign_to_issue, session, issue, reposlug,
                                   strategy, config_rules, dry_run)
                    tasks.append(loop.run_in_executor(None, func))
            for task in tasks:
                await task
    except IssuesListException as e:
        click.secho('ERROR', fg='red', bold=True, nl=False, err=True)
        click.echo(f': Could not list issues for repository {reposlug}',
            err=True)
        exit(10)


@click.command()
@click.option('-s', '--strategy',
    type=click.Choice(['append', 'set', 'change']), default='append',
    show_default=True, help='How to handle assignment collisions.')
@click.option('-d', '--dry-run', is_flag=True,
    help='Run without making any changes.')
@click.option('-x', '--async', 'use_async', is_flag=True,
    help='Send the requests to GitHub API in an asynchronous fashion.')
@click.option('-a', '--config-auth', type=click.File('r'), required=True,
    callback=parse_auth, help='File with authorization configuration.')
@click.option('-r', '--config-rules', type=click.File('r'), required=True,
    callback=parse_rules, help='File with assignment rules configuration.')
@click.argument('reposlug', nargs=-1, required=True, callback=validate_reposlug)
def run(strategy, dry_run, use_async, config_auth, config_rules, reposlug):
    """CLI tool for automatic issue assigning of GitHub issues"""

    if use_async:
        asyncio.run(process_all_async(reposlug, config_auth, config_rules,
                    strategy, dry_run))
    else:
        process_all(reposlug, config_auth, config_rules, strategy, dry_run)


def main():
    run(prog_name='ghia')