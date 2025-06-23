TAG := bdk-reserves
TAG_63 := bdk-reserves-63
http_proxy ?= http://172.17.0.1:3128
DOCKER_RUN := docker run --interactive --rm \
	-v ${PWD}:/home/satoshi \

build: builder
	$(DOCKER_RUN) --tty ${TAG} cargo build

test: test_current test_63

test_current: builder
	rm -f Cargo.lock
	$(DOCKER_RUN) ${TAG} cargo test

test_63: builder_63
	rm -f Cargo.lock
	$(DOCKER_RUN) ${TAG_63} cargo test || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p zstd-sys --precise "2.0.8+zstd.1.5.5" || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p time --precise "0.3.20" || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p home --precise "0.5.5" || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p flate2 --precise "1.0.35" || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p bzip2-sys --precise "0.1.12" || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p ring --precise "0.17.12" || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p once_cell --precise "1.20.3" || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p base64ct --precise "1.6.0" || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p minreq --precise "2.13.2" || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p bdk_electrum --precise 0.20.1 || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p rustls:0.23.28 --precise 0.23.12 || true
	$(DOCKER_RUN) ${TAG_63} cargo test

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

builder_63:
	docker build --tag ${TAG_63}\
		--build-arg http_proxy="${http_proxy}" \
		--build-arg UID="$(shell id -u)" \
		-f Dockerfile_63 \
		.

