pyblst
=======
[![CI](https://github.com/OpShin/pyblst/actions/workflows/CI.yml/badge.svg)](https://github.com/OpShin/pyblst/actions/workflows/CI.yml)
[![Build Status](https://app.travis-ci.com/OpShin/pyblst.svg?branch=master)](https://app.travis-ci.com/OpShin/pyblst)
[![PyPI version](https://badge.fury.io/py/pyblst.svg)](https://pypi.org/project/pyblst/)
[![PyPI - Status](https://img.shields.io/pypi/status/pyblst.svg)](https://pypi.org/project/pyblst/)

This package supplies python bindings for the library [blst](https://github.com/supranational/blst).
The bindings are added on a per-need basis, currently only serving the development of [OpShin](https://github.com/opshin)


### Installation

Install python3. Then run the following command.

```bash
python3 -m pip install pyblst
```

### Usage


```python


```

### Building

In case you need to build this package from source, install Python3 and Rust and proceed as follows.

```bash
git clone https://github.com/OpShin/pyblst
cd pyblst
python3 -m venv .env
source .env/bin/activate  # or in whichever environment you want to have it installed
pip install maturin
maturin build
```

The package will be installed in the active python environment.
