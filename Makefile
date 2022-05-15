.SHELLFLAGS = -ec
.ONESHELL:

.PHONY: init
init:
	pip install -r requirements.txt


.PHONY: test
test:
	pytest tests

.PHONY: publish-test
publish-test:
	if [ -z "$$TWINE_USERNAME" ]; then
		echo "TWINE_USERNAME not set" >&2
		exit 1
	fi

	if [ -z "$$TWINE_PASSWORD" ]; then
		echo "TWINE_PASSWORD not set" >&2
		exit 1
	fi

	python setup.py sdist bdist_wheel
	twine check dist/*

	twine upload \
		--non-interactive \
		--repository-url https://test.pypi.org/legacy/ \
		dist/*

	@echo "Published to TestPyPI. To try installing, do:" >&2
	@echo "  pip install -i https://test.pypi.org/simple/ \\" >&2
	@echo "    --extra-index-url https://pypi.org/simple/ \\" >&2
	@echo "    aws-iam-utils" >&2
	@echo "" >&2

.PHONY: clean
clean:
	rm -rf dist build
