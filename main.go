package main

import (
	"github.com/docker/machine/libmachine/drivers/plugin"
	"github.com/sofianinho/docker-machine-driver-pwd/pwd"
)

func main() {
	plugin.RegisterDriver(new(pwd.Driver))
}
