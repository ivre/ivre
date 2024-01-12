# How to contribute

You'll find here tips and advices to help you contribute to IVRE in
the most efficient way.

## Project objectives

IVRE does not include scanners or network analyzers, it only feeds a
database with data from such programs (Nmap, Masscan, Zeek, etc.) and
provide tools to use the collected data.

We believe that it is important to keep the raw (uninterpreted) data
in the database, together with data interpretation.

We try to support as many network discovery tools as possible, to keep
and make the code (and the commit history) as clean as possible.

Since IVRE can be slow on some tasks (particularly, when importing
huge data sets), we try to limit CPU and memory usage (and sometimes
this has a negative impact on the code quality and readability).

## How to communicate?

Once you have decided you want to contribute something, open an issue
(or update an existing issue) to let other people know you're working
on it and track your progress.

You might want to ask whether you're working in an good direction, to
avoid the frustration of seeing your contribution rejected after a lot
of work.

## Reporting issues

### Security issues

If you want to report an issue privately to IVRE's developers, please
send an email `dev` on the domain `ivre.rocks`. We will answer your
mail as soon as we can to see how we can fix the vulnerability, how
long it will take, and agree on a fix release and vulnerability
disclosure agenda.

### Questions

It is OK so submit issues to ask questions (more than OK,
encouraged). There is a label "question" that you can use for that.

### Bugs

If you have installed IVRE through a package manager or are not using
the development version, please get and install the current
development code, and check that the bug still exists before
submitting an issue.

If you're not sure whether a behavior is a bug or not, submit an issue
and ask, don't be shy!

### Enhancements / feature requests

If you want a feature in IVRE, but cannot implement it yourself or
want some hints on how to do that, open an issue with label
"enhancement".

Explain if possible the API you would like to have (e.g., give examples
of function calls, packet creations, etc.).

## Submitting pull requests

### Dependencies

We try to minimize the number of programs we depend on. When we decide
to depend on an external program, we try to be as tolerant as possible
on the required version.

Introducing a dependency or reducing the acceptable versions for a
dependency must only be done when it makes the code much easier to
read and maintain: the benefits must be important, since each new
dependency makes it harder for users to install IVRE.

### Coding style & conventions

We try to comply with the some guidelines for new code:

-   The code **must** be compatible with Python 3.7 to 3.12.

-   The code should be PEP-8 compliant; you can check your code with
    [pep8](https://pypi.python.org/pypi/pep8).

-   [Pylint](https://pylint.org/) can help you write good Python
    code (even if respecting Pylint rules is sometimes either too hard
    or even undesirable; human brain needed!).

-   [Black](https://github.com/psf/black) has to be used to format
    Python code in IVRE.

-   [flake8](https://flake8.pycqa.org/),
    [mypy](http://mypy-lang.org/), Black and Pylint tests are run for
    each pull request (see `.github/workflows/linting.yml` for the
    specific options). Pull requests will not be accepted when the
    tests fail.

-   [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
    is a nice read!

-   Avoid creating `list` objects when generators can be used,
    particularly if they can be huge:

    -   Use `for line in fdesc` instead of `for line in fdesc.readlines()`.
    -   More generally, prefer generators over lists.

We do not accept PEP-8 fixes or similar contributions, because they
break the code history that we use a lot. If you change code, it's OK
(and even reconmmended) to include PEP-8 fixes **for the lines you
need to change** and **only for these lines**.

### Tests

Please consider adding tests for each new feature and for each bug
fixed. This will prevent a regression from being unnoticed.

Pull requests will not be accepted if the tests fail.

### Code review

Maintainers tend to be picky, and you might feel frustrated that your
code (which is perfectly working in your use case) is not merged
faster.

Please don't be offended, and keep in mind that maintainers are
concerned about code maintainability and readability, commit history
(we use the history a lot, for example to find regressions or
understand why certain decisions have been made), performances, API
consistency, etc.

**Thanks for reading, happy hacking!**
