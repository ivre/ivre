#! /bin/bash

if [ "$DB" = "maxmind" ]; then
    if [ "$TRAVIS_PYTHON_VERSION" = 3.9 ]; then
	if ! black -t py36 --check ./doc/conf.py ./setup.py ./bin/ivre ./tests/tests.py ./ivre_bak/; then
	    echo "black KO"
	    exit -1
	fi
	echo "black OK"
	if ! codespell  --ignore-words=.travis/codespell_ignore `git ls-files | grep -vE '^web/static/(doc|an|bs|d3|jq|lk)/|^data/|\.(png|gif|svg)$'`; then
	    echo "codespell KO"
	    exit -1
	fi
	echo "codespell OK"
	if ! pylint -e all -d abstract-method,arguments-differ,attribute-defined-outside-init,broad-except,duplicate-code,fixme,function-redefined,global-statement,global-variable-undefined,import-error,invalid-name,locally-disabled,missing-docstring,no-absolute-import,no-member,protected-access,raise-missing-from,subprocess-popen-preexec-fn,super-init-not-called,suppressed-message,too-few-public-methods,too-many-ancestors,too-many-arguments,too-many-boolean-expressions,too-many-branches,too-many-instance-attributes,too-many-lines,too-many-locals,too-many-nested-blocks,too-many-public-methods,too-many-return-statements,too-many-statements,unsubscriptable-object,unused-argument,line-too-long ivre ./doc/conf.py ./setup.py ./bin/ivre; then
	    echo "pylint KO"
	    exit -1
	fi
	echo "pylint OK"
    fi
    if ! flake8 --ignore=E402,E501,F401 ./doc/conf.py && flake8 --ignore=E501,W503 ./setup.py ./bin/ivre && flake8 --ignore=E203,E402,E501,W503 ./tests/tests.py && flake8 --ignore=E203,E501,W503 ./ivre_bak/; then
	echo "flake8 KO"
	exit -1
    fi
    echo "flake8 OK"
    mv ivre_bak ivre
    if ! mypy ./ivre/{config,flow,graphroute,utils}.py; then
	echo "mypy KO"
	exit -1
    fi
    mv ivre ivre_bak
    echo "mypy OK"

fi

cd tests/ && \
    coverage erase && \
    coverage run --parallel-mode tests.py --coverage && \
    coverage combine && \
    coverage report -i
