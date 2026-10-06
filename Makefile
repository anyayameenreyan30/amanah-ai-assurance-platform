OPA_VERSION ?= v1.4.2
.PHONY: install opa demo test policy-test docker clean
install:
	pip install -r requirements.txt
opa:
	mkdir -p bin && curl -sSL -o bin/opa https://github.com/open-policy-agent/opa/releases/download/$(OPA_VERSION)/opa_linux_amd64_static && chmod +x bin/opa
demo:
	python -m amanah demo
policy-test:
	bin/opa test policies -v
test: policy-test
	pytest -q
docker:
	docker compose up --build
clean:
	rm -rf var
