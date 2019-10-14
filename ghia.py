import configparser
import re

import click
import requests


valid_reposlug = re.compile('^[^/]+/[^/]+$')


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
                rules['patterns'][name.lower()].split('\n')
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