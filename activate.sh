if [ -s ./.venv ] ; then
	source ./.venv/bin/activate ;
else
	echo 'No venv defined, creating...' ;
	python -m venv .venv ;
	source ./.venv/bin/activate ;
	PIP_CONFIG_FILE=pip.conf pip install -r requirements.txt
	pre-commit install
fi;
