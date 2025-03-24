package main

import (
	"agent/common"
	"agent/router"
	agent "github.com/cdlicn/gazer-agent"
)

func main() {
	agent.Run()

	common.Init()

	r := router.Router()
	r.Run(":8080")
}
