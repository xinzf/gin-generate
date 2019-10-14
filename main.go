package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	name         string
	workspace    string
	project_path string
	workspace_tt = flag.String("workspace", "", "工作区")
	name_tt      = flag.String("name", "", "项目名称")
	gopath       = os.Getenv("GOPATH")
	root_path    string
)

func init() {
	flag.Parse()

	workspace = strings.TrimLeft(strings.TrimRight(*workspace_tt, "/"), "/")
	name = strings.TrimLeft(strings.TrimRight(*name_tt, "/"), "/")

	project_path = workspace + "/" + name

	if gopath == "" {
		panic("GOPATH has not set.")
	}

	root_path = gopath + "/src/" + project_path
}

func main() {
	if workspace == "" {
		fmt.Println("请提供工作区路径")
		return
	}
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
	writeErrnoCode()
	writeErrnoErrno()
	writeConsul()
	writeNode()
	writeRouter()
	writeMiddlewareAuthorize()
	writeMiddlewareLogger()
	writeServer()
	writeMakefile()
	writeHttpClient()
	writeStorageInit()
	writeMongo()
	writeMysql()
	writeRedis()
	writeResponse()
	writeMock()
	writeUtilsConvert()
	writeTest()
}
