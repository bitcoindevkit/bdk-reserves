TAG := bdk-reserves
TAG_57 := bdk-reserves-57
TAG_63 := bdk-reserves-61
http_proxy ?= http://172.17.0.1:3128
DOCKER_RUN := docker run --interactive --rm \
	-v ${PWD}:/home/satoshi \

build: builder
	$(DOCKER_RUN) --tty ${TAG} cargo build

test: test_current test_63

test_current: builder
	rm -f Cargo.lock
	$(DOCKER_RUN) ${TAG} cargo test

test_57: builder_57
	#rm -f Cargo.lock
	#$(DOCKER_RUN) ${TAG_57} cargo update -p log:0.4.20 --precise 0.4.18
	#$(DOCKER_RUN) ${TAG_57} cargo update -p tempfile --precise 3.6.0
	#$(DOCKER_RUN) ${TAG_57} cargo update -p sct:0.7.1 --precise 0.7.0
	$(DOCKER_RUN) ${TAG_57} cargo update -p zip:0.6.6 --precise 0.6.3 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p rustls:0.21.10 --precise 0.21.1 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p rustls:0.21.7 --precise 0.21.1 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p rustls:0.21.4 --precise 0.21.1 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p rustls:0.21.2 --precise 0.21.1 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p rustls:0.20.9 --precise 0.20.8 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p rustls-webpki:0.100.3 --precise 0.100.1 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p rustls-webpki:0.101.4 --precise 0.101.1 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p rustls-webpki:0.101.7 --precise 0.101.1 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p crossbeam-utils:0.8.18 --precise 0.8.16 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p tokio:1.35.1 --precise 1.29.1 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p rustix:0.38.9 --precise 0.38.3 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p ring:0.17.7 --precise 0.16.20 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p byteorder:1.5.0 --precise 0.4.3 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p webpki:0.22.4 --precise 0.22.0 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p crossbeam-epoch:0.9.17 --precise 0.9.15 || true
	$(DOCKER_RUN) ${TAG_57} cargo update -p byteorder:1.5.0 --precise 0.4.3 || true
	$(DOCKER_RUN) ${TAG_57} cargo test

test_63: builder_63
	rm -f Cargo.lock
	$(DOCKER_RUN) ${TAG_63} cargo test || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p home:0.5.9 --precise 0.5.5 || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p tokio:1.39.3 --precise 1.38.1 || true
	$(DOCKER_RUN) ${TAG_63} cargo update -p cc --precise 1.0.105 || true
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

builder_57:
	docker build --tag ${TAG_57}\
		--build-arg http_proxy="${http_proxy}" \
		--build-arg UID="$(shell id -u)" \
		-f Dockerfile_57 \
		.

builder_63:
	docker build --tag ${TAG_63}\
		--build-arg http_proxy="${http_proxy}" \
		--build-arg UID="$(shell id -u)" \
		-f Dockerfile_63 \
		.

