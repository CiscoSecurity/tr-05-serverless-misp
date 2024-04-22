NAME:="tr-05-misp"
PORT:="9090"

all: test build scout

run: # app locally
	cd code; python -m main; cd -

black:
	black code/ -l 120 -t py39 --exclude=payloads_for_tests.py
build: stop
	docker build -q -t $(NAME) .;
	docker run -dp $(PORT):$(PORT) --name $(NAME) $(NAME)
stop:
	docker stop $(NAME); docker rm $(NAME); true
lint: black
	flake8 code/
test: lint
	cd code; coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report --fail-under=80; cd -
test_lf:
	cd code; coverage run --source api/ -m pytest --verbose -vv --lf tests/unit/ && coverage report; cd -
scout:
	docker scout cves $(NAME)
	pip-audit
scout_install:
	curl -sSfL https://raw.githubusercontent.com/docker/scout-cli/main/install.sh | sh -s --

# --------------------------------------------------------------------- #
# If ngrok can be used by you then you can run below make commands
# --------------------------------------------------------------------- #
up: down build expose
down: unexpose stop

expose:
	ngrok http $(PORT) > /dev/null &
echo_ngrok:
	curl -s localhost:4040/api/tunnels | jq -r ".tunnels[0].public_url"
unexpose:
	pkill ngrok; true
