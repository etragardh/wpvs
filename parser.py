import argparse
class parser:

    def create():

        parser = argparse.ArgumentParser(
            prog='WP Vuln Scan',
            description='Utility to scan CNAs for vulns',
            epilog="Be nice"
        )
        parser.add_argument(
            '-y', '--version',
            action='store_true',
            help='Display version'
        )
        parser.add_argument(
            '-a', '--age',
            default=30,
            help='Look this many days in the past'
        )
        parser.add_argument(
            '-t', '--threads',
            default=500,
            help='Amount of threads'
        )
        parser.add_argument(
            '--cvss-min',
            default=0.0,
            help='Minimum CVSS'
        )
        parser.add_argument(
            '--cvss-max',
            default=10.0,
            help='Maximum CVSS'
        )
        parser.add_argument(
            '--unauth-only',
            action='store_true',
            help='Unauthenticated only'
        )
        parser.add_argument(
            '--type',
            nargs='*',
            help='What vulnerability type to include'
        )
        parser.add_argument(
            '--slug',
            help='Search specific plugin and/or theme'
        )
        parser.add_argument(
            '--purge',
            action='store_true',
            help='Purge cache'
        )
        parser.add_argument(
            '-d', '--debug',
            default=0,
            nargs='?',
            help='Debug, verbose level 1-3'
        )
        return parser
