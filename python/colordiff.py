import difflib
try:
    from colorama import Fore, Back, Style, init
    init()
except ImportError:  # fallback so that the imported classes always exist
    class ColorFallback():
        __getattr__ = lambda self, name: ''
    Fore = Back = Style = ColorFallback()

def color_diff(diff):
    for line in diff:
        if line.startswith('+'):
            yield Fore.GREEN + str(line) + Fore.RESET
        elif line.startswith('-'):
            yield Fore.RED + str(line) + Fore.RESET
        elif line.startswith('^'):
            yield Fore.BLUE + str(line) + Fore.RESET
        else:
            yield str(line)

def packetdiff(firstBytes,secondBytes):
    diff = difflib.ndiff(firstBytes, secondBytes)
    diff = color_diff(diff)
    print(''.join(diff).replace(' ',''))