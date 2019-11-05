import configparser
import click
import re


valid_types = ['title', 'text', 'label', 'any']


def parse_auth_configparse(auth):
    if not 'github' in auth or not 'token' in auth['github']:
        raise Exception

    return {
        'token': auth['github']['token'],
        'secret':
            auth['github']['secret'] if 'secret' in auth['github'] else None
    }


def parse_auth(ctx, param, value):
    error_text = 'incorrect configuration format'
    auth = configparser.ConfigParser()
    try:
        auth.read_file(value)
        return parse_auth_configparse(auth)
    except:
        raise click.BadParameter(error_text)



def parse_rules_configparse(rules):
    if not 'patterns' in rules:
        raise Exception

    fallback = None
    if 'fallback' in rules:
        if not 'label' in rules['fallback']:
            raise Exception

        fallback = rules['fallback']['label']

    parsed_rules = []
    for name in rules['patterns']:
        parsed_rule = {
            'name': name,
            'rules': {type: [] for type in valid_types}
        }

        # Filter out empty lines and split the rest to tag and pattern
        lines = map(
            lambda line: line.split(':', 1), filter(
                lambda line: line != '',
                rules['patterns'][name].split('\n')
        ))

        for line in lines:
            if not line[0] in parsed_rule['rules']:
                raise Exception

            try:
                regex = re.compile(line[1], flags=re.IGNORECASE)
            except:
                raise Exception

            parsed_rule['rules'][line[0]].append(regex)

        parsed_rules.append(parsed_rule)

    return {'fallback': fallback, 'rules': parsed_rules}


def parse_rules(ctx, param, value):
    error_text = 'incorrect configuration format'
    rules = configparser.ConfigParser()
    rules.optionxform=str
    try:
        rules.read_file(value)
        return parse_rules_configparse(rules)
    except:
        raise click.BadParameter(error_text)


def print_diff(new, old):
    for user in sorted(new | old, key=str.casefold):
        if user not in new:
            click.echo(f'   {click.style("-", bold=True, fg="red")} {user}')

        elif user not in old:
            click.echo(f'   {click.style("+", bold=True, fg="green")} {user}')

        else:
            click.echo(f'   {click.style("=", bold=True, fg="blue")} {user}')