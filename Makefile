TAG := bdk-reserves
TAG_85 := bdk-reserves-85
#http_proxy ?= http://172.17.0.1:3128
DOCKER_RUN := docker run --interactive --rm \
	-v ${PWD}:/home/satoshi \

build: builder
	$(DOCKER_RUN) --tty ${TAG} cargo build

test: test_current test_85

test_current: builder
	rm -f Cargo.lock
	$(DOCKER_RUN) ${TAG} cargo test

test_85: builder_85
	rm -f Cargo.lock
	$(DOCKER_RUN) ${TAG_85} cargo test || true
	#$(DOCKER_RUN) ${TAG_85} cargo update -p home --precise "0.5.9" || true
	#$(DOCKER_RUN) ${TAG_85} cargo update -p minreq --precise "2.13.2" || true
	$(DOCKER_RUN) ${TAG_85} cargo test

run: builder
	$(DOCKER_RUN) --tty ${TAG} cargo run

wasm-unknown: builder
	$(DOCKER_RUN) --tty ${TAG} cargo check --target wasm32-unknown-unknown --no-default-features

wasm-wasi: builder
	$(DOCKER_RUN) --tty ${TAG} cargo check --target wasm32-wasi --no-default-features

wasm-emscripten: builder
	$(DOCKER_RUN) --tty ${TAG} cargo check --target wasm32-unknown-emscripten --no-default-features

sh: builder
	$(DOCKER_RUN) --tty ${TAG} sh

builder:
	docker build --tag ${TAG} \
		--build-arg http_proxy="${http_proxy}" \
		--build-arg UID="$(shell id -u)" \
		.

builder_85:
	docker build --tag ${TAG_85}\
		--build-arg http_proxy="${http_proxy}" \
		--build-arg UID="$(shell id -u)" \
		-f Dockerfile_85 \
		.

