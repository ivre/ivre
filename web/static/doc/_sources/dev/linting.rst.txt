Code linting
============

IVRE uses code linters to prevent some easy-to-spot (for a computer)
mistakes and to enforce a consistent code style (or at least, attempt
to do so).

So far, only the Python code uses such linters (`Flake8
<https://flake8.pycqa.org>`_ and `Pylint
<https://www.pylint.org/>`_). Adding similar code linting capabilities
to the Zeek scripts (`zeek/`), LUA (`nmap_scripts/`) and JavaScript /
HTML (`web/static/`) could be a good PR idea!

For all the code and the documentation, we also use `Codespell
<https://github.com/codespell-project/codespell>`_ to prevent typos.

Running the linters
-------------------

To install the Python code linters and Codespell you can simply use
the `requirements-linting.txt` file with Pip, or use any method to
install the latest versions of the `codespell`, `flake8` and `pylint`
Python modules.

The script `pkg/runchecks` will run all the tests for you with the
expected options and exceptions.


Travis CI
---------

Code linting and spell checking is performed in Travis CI (see
:ref:`dev/tests:Travis CI`), togethter with the Maxmind tests. Pylint
and Codespell only run with Python 3.8, while Flake8 runs with all
Python versions.
