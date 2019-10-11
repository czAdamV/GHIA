import click

@click.command()
@click.option('-s', '--strategy',
    type=click.Choice(['append', 'set', 'change']), default='append',
    show_default=True, help='How to handle assignment collisions.')
@click.option('-d', '--dry-run', is_flag=True,
    help='Run without making any changes.')
@click.option('-a', '--config-auth', type=click.File('r'), required=True,
    help='File with authorization configuration.')
@click.option('-r', '--config-rules', type=click.File('r'), required=True,
    help='File with assignment rules configuration.')
@click.argument('reposlug')
def run(strategy, dry_run, config_auth, config_rules, reposlug):
    """CLI tool for automatic issue assigning of GitHub issues"""
    pass

if __name__ == '__main__':
    run()