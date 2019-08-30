TAG := $(shell git rev-parse --short HEAD)
DIR := $(shell pwd -L)

dep:
	docker run -ti \
        --mount src="$(DIR)",target="$(DIR)",type="bind" \
        -w "$(DIR)" \
        asecurityteam/sdcli:v1 go dep

lint:
	docker run -ti \
        --mount src="$(DIR)",target="$(DIR)",type="bind" \
        -w "$(DIR)" \
        asecurityteam/sdcli:v1 go lint

test:
	docker run -ti \
        --mount src="$(DIR)",target="$(DIR)",type="bind" \
        -w "$(DIR)" \
        asecurityteam/sdcli:v1 go test

integration:
	DIR=$(DIR) \
	docker-compose \
		-f docker-compose.it.yml \
		up \
			--abort-on-container-exit \
			--build \
			--exit-code-from test

coverage:
	docker run -ti \
        --mount src="$(DIR)",target="$(DIR)",type="bind" \
        -w "$(DIR)" \
        asecurityteam/sdcli:v1 go coverage

doc: ;

build-dev: ;

build: ;

run:
	docker-compose up --build --abort-on-container-exit

deploy-dev: ;

deploy: ;
