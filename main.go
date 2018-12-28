package main

import (
	"flag"
	"fmt"
	"os"
)

var (
	name      string
	tt        = flag.String("name", "", "项目路径")
	gopath    = os.Getenv("GOPATH")
	root_path string
)

func init() {
	flag.Parse()

	name = *tt

	if gopath == "" {
		panic("GOPATH has not set.")
	}

	root_path = gopath + "/src/" + name
}

func main() {
	if name == "" {
		fmt.Println("请提供项目路径")
		return
	}
	MkDirs()
	writeMain()
	writeConfigYaml()
	writeConfig()
	writeBaseHandler()
	writeHomeHandler()
	writeModelInit()
	writeErrnoCode()
	writeErrnoErrno()
	writeConsul()
	writeNode()
	writeRouter()
	writeMiddlewareAuthorize()
	writeMiddlewareHeader()
	writeMiddlewareLogger()
	writeUtilsPool()
	writeUtilsTools()
	writeServer()
	writeMakefile()
}
