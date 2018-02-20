# docker-machine-pwd-driver

Docker machine PWD driver


## Getting started

This driver tricks machine and allows to create / remove [play-with-docker](http://play-with-docker.com) instances remotely.

Before using it please make sure of the following:

- Create a session in PWD and set PWD_URL env variable or use --pwd-url flag when creating an instance

## Compiling from source

Use [glide](https://glide.sh/) to install dependencies (needs to have a proper goland setup)

```sh
glide install
```

Compile simply with:

```sh
go build
```

To have a statically linked binary:

```sh
CGO_ENABLED=0 go build -a -installsuffix nocgo  .
```

## Installing

### Easy way

Download the release bundle from the [releases](https://github.com/play-with-docker/docker-machine-driver-pwd/releases) section and place the binary that corresponds to your platform it somewhere in your PATH



### Hard way

Use `go get github.com/play-with-docker/docker-machine-driver-pwd` and make sure that
`docker-machine-driver-pwd` is located somewhere in your PATH



## Usage

- Creating an instance:

```
# Create a session in play-with-docker.com and set the PWD_URL env variable
docker-machine create -d pwd --pwd-url <pwd_url> node1
eval $(docker-machine env node1)
docker ps
```

Alternatively you can set the env variable `PWD_URL` to avoid passing it as a flag every time.


- Remove an instance


```
docker-machine rm -f node1
```

- Which session am I using

```
docker-machine inspect node1
```
Have a look at the "Driver" section for this information.


## Development

For local development it's necessary to set `PWD_PORT`, `PWD_HOSTNAME` and `PWD_SSL_PORT`
accordingly to use with local PWD.

i.e:

```
export PWD_PORT=3000
export PWD_SSL_PORT=3001
```

## changelog

- I changed the way pwd asks for a session. It does not need to have the playground url with a "/p/ID_OF_YOUR_PLAYGROUND" in it. If you give it a playground, it will create a sandbox in it (if it exists), or else it will create a session and sandbox in it. This parameters can be seen using the command "docker-machine inspect YOUR_MACHINE"

- In order to achieve this, I had to modify the play-with-docker version by returning a JSON when you create a new session (instead of nothing). This json looks like below. This change can be done in the handlers/new_session.go

```json
{"session_id":"ac95f9e1-093b-4fe8-af79-5a3180d41e89","hostname":"playground.localhost"}
```
