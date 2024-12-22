## Print in Color

import json
from tabulate import tabulate

#
# I include some more colors if you want to change them later
#

BLACK = "\033[0;30m"
RED = "\033[0;31m"
GREEN = "\033[0;32m"
#BROWN = "\033[0;33m" # This is YELLOW
BLUE = "\033[0;34m"
PURPLE = "\033[0;35m"
CYAN = "\033[0;36m"
LIGHT_GRAY = "\033[0;37m"
YELLOW = "\033[0;33m"
DARK_GRAY = "\033[1;30m"
LIGHT_RED = "\033[1;31m"
LIGHT_GREEN = "\033[1;32m"
LIGHT_YELLOW = "\033[1;33m"
LIGHT_BLUE = "\033[1;34m"
LIGHT_PURPLE = "\033[1;35m"
LIGHT_CYAN = "\033[1;36m"
LIGHT_WHITE = "\033[1;37m"
B    = "\033[1m"
BOFF = "\033[22m"
FAINT = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"
BLINK = "\033[5m"
NEGATIVE = "\033[7m"
CROSSED = "\033[9m"
END = "\033[0m"
DANGER = RED+B+NEGATIVE+BLINK

class CPrint:

    debug_lvl = False # False | 1 | 2 | 3

    def __init__(self, debug = False, **kwargs):
        self.version = '0.1'
        
        # Fix for present but not specified (--debug)
        # Set debug level
        self.debug_lvl = 1 if debug == None else int(debug)

        if 'other_arg' in kwargs:
            print('there were other arg') # Prepare for setting custom colors

    def enable_debug(self, n=1):
        # Set debug level
        self.debug_lvl = int(n)

    def version(self):
        self.success('CPrint version: ' + self.version)

    def info(self, *args, **kwargs):
        for arg in args:
            self.echo(arg, '-', LIGHT_GRAY, kwargs)

    def bold(self, *args, **kwargs):
        for arg in args:
            self.echo(arg, '!', END, kwargs)

    def success(self, *args, **kwargs):
        for arg in args:
            self.echo(arg, '+', GREEN, kwargs)

    def warn(self, *args, **kwargs):
        for arg in args:
            self.echo(arg, 'x', YELLOW, kwargs)

    def error(self, *args, **kwargs):
        for arg in args:
            self.echo(arg, 'x', RED, kwargs)

    def debug(self, *args, **kwargs):
        print('====')
        raise Exception("Deprecated")

        if not self.debug_lvl:
            return None

        for arg in args:
            self.echo(arg, 'D', CYAN, kwargs)

    def v(self, *args, **kwargs):
        if self.debug_lvl >= 1:
            for arg in args:
                self.echo(arg, '1', CYAN, kwargs)

    def vv(self, *args, **kwargs):
        if self.debug_lvl >= 2:
            for arg in args:
                self.echo(arg, '3', CYAN, kwargs)

    def vvv(self, *args, **kwargs):
        if self.debug_lvl >= 3:
            for arg in args:
                self.echo(arg, '3', CYAN, kwargs)

    # args only for prefix
    def echo(self, text, x = '+', color = "\033[37m", args={}):
        prefix = '' if not 'prefix' in args else args['prefix']
      
        # Convert bytes to str
        if isinstance(text, bytes):
            text = text.decode('utf-8')

        # Handle strings
        if isinstance(text, str):
          if "\n" in text:
            for line in text.split("\n"):
              self.echo(line, x, color, {"prefix":prefix})
            return  
          print(LIGHT_GRAY+"["+color+B+x+LIGHT_GRAY+BOFF+"] " + prefix + text + END)

        # Handle all else:
        else:
          print(LIGHT_GRAY+"["+color+B+x+LIGHT_GRAY+BOFF+"]" + prefix, text, END)

    def table(self, head, rows):
        head = head if head else []
        rows = rows if rows else []
        print(tabulate(rows, headers=head, tablefmt='orgtbl'))
