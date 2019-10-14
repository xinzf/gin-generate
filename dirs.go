package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func MkDirs() {
	dirs := []string{
		"conf",
		"core",
		"core/config",
		"core/httpclient",
		"core/mock",
		"core/registry",
		"core/storage",
		"core/utils",
		"server",
		"server/errno",
		"server/handlers",
		"server/models",
		"server/protocols",
		"server/router",
		"server/router/middleware",
		"server/services",
		"server/services/dao",
		"server/services/requests",
		"tests",
	}

	for _, path := range dirs {
		path = root_path + "/" + path
		exist, err := PathExists(path)
		if err != nil {
			continue
		}

		if !exist {
			os.MkdirAll(path, os.ModePerm)
		}
		fmt.Println("Create path: ", path+" success.")
	}
}

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}

	if os.IsNotExist(err) {
		return false, nil
	}

	return false, err
}

func CurrentPath() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatal(err)
	}
	return dir
	//return strings.Replace(dir, "\\", "/", -1)
}

func write(filename, data string) {
	f, _ := os.Create(filename)
	defer f.Close()

	f.WriteString(data)
	fmt.Println("Create file：" + filename + " success.")
}
