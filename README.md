# windex

[![PyPI](https://img.shields.io/pypi/v/windex.svg)](https://pypi.org/project/windex/)
[![Changelog](https://img.shields.io/github/v/release/gilad.reti@gmail.com/windex?include_prereleases&label=changelog)](https://github.com/gilad.reti@gmail.com/windex/releases)
[![Tests](https://github.com/gilad.reti@gmail.com/windex/actions/workflows/test.yml/badge.svg)](https://github.com/gilad.reti@gmail.com/windex/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/gilad.reti@gmail.com/windex/blob/master/LICENSE)

windows binary index

## Installation

Install this tool using `pip`:
```bash
pip install windex
```

For patchdiffing, make sure ida9 is installed and available via:
```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$IDA/plugins:$IDA
export PYTHOHNPATH=$PYTHONPATH:$IDA/python/3:$IDA/python/3/ida_64:$IDA/plugins
pip install $IDA/idalib/python
```

## Usage

For help, run:
```bash
windex --help
```
You can also use:
```bash
python -m windex --help
```

### `listdiff`
lists the files changed in a given patch tuesday.

### `patchdiff`
indexes and lists the patches in a given file in a given patch tuesday.

### `browse`
experimental. allows browsing for available files in `winbindex`'s database.

## Development

To contribute to this tool, first checkout the code. Then create a new virtual environment:
```bash
cd windex
python -m venv venv
source venv/bin/activate
```
Now install the dependencies and test dependencies:
```bash
pip install -e '.[test]'
```
To run the tests:
```bash
python -m pytest
```

## Credits
Many thanks to [m417z](https://m417z.com/) for the very great [winbindex](https://winbindex.m417z.com/).