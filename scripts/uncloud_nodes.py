"""Company-derived node names, retaining saved names only for existing installs."""
import re


def node_names(company, saved=None):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,39}', company):
        raise ValueError('Invalid company name for a two-node deployment')
    if not saved:
        return (company + '-a', company + '-b')
    names = tuple(sorted(saved))
    if (len(names) != 2 or not re.fullmatch(r'[a-z0-9][a-z0-9-]*-a', names[0])
            or names[1] != names[0][:-1] + 'b'):
        raise ValueError('Expected two saved company nodes ending in -a and -b')
    return names
