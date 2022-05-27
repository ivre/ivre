Code linting
============

IVRE uses code linters to prevent some easy-to-spot (for a computer)
mistakes and to enforce a consistent code style (or at least, attempt
to do so).

So far, only the Python code uses such linters (`Flake8
<https://flake8.pycqa.org>`_, `Pylint <https://pylint.org/>`_, `Mypy
<http://mypy-lang.org/>`_ and `Black
<https://github.com/psf/black>`_). Adding similar code linting
capabilities to the Zeek scripts (`zeek/`), LUA
(`patches/nmap/scripts/`) and JavaScript / HTML (`web/static/`) could
be a good PR idea!

For all the code and the documentation, we also use `Codespell
<https://github.com/codespell-project/codespell>`_ to prevent typos.

Running the linters
-------------------

To install the Python code linters and Codespell you can simply use
the `requirements-linting.txt` file with Pip, or use any method to
install the latest versions of the `black`, `codespell`, `flake8` and
`pylint` Python modules.

The script `pkg/runchecks` will run all the tests for you with the
expected options and exceptions.


GitHub actions
--------------

Code linting and spell checking is performed in a dedicated `GitHub
action <https://github.com/ivre/ivre/actions/workflows/linting.yml>`_
(see :ref:`dev/tests:GitHub actions`), togethter with the Maxmind
tests. Pylint and Codespell only run with Python 3.10, while Flake8
runs with all Python versions.
