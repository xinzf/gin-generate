package main

import (
	"fmt"
	"strings"
)

func writeMain() {
	str := fmt.Sprintf(`package main

import (
	"context"
	log "github.com/sirupsen/logrus"
	"%s/server"
	"%s/server/config"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

const (
	// @todo change your project name and version...
	PROJECT_NAME = "%s"
	VERSION      = "1.1.0"
)

func init() {

}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	ex := make(chan bool)
	go run(ex)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

	<-ch
	close(ex)

	if err := server.Deregister(); err != nil {
		log.Errorln(err)
	}

	if err := server.Stop(); err != nil {
		log.Errorln(err)
	}
}

func run(ex chan bool) {

	ctx := context.WithValue(context.TODO(), "project_info", map[string]string{
		"name":    PROJECT_NAME,
		"version": VERSION,
	})

	if err := config.Init(ctx); err != nil {
		log.Panic(err)
	}

	server.Init(ctx)
	if err := server.Start(); err != nil {
		log.Panic(err)
	}

	if err := server.Register(); err != nil {
		log.Panic(err)
	}

	for {
		select {
		case <-ex:
			return
		}
	}
}`, project_path, project_path, strings.ToUpper(name))

	write(root_path+"/main.go", str)
}

func writeConfigYaml() {
	str := `runmode: debug   # 开发模式, debug, release, test

server:
#  addr: 0.0.0.0
#  port: 5001

#consul: true

db:
  dbserviceName:
    master:
      host: "mysql host"
      name: "mysql db name"
      user: "root"
      pswd: "111111"
    openConns: 20
    idleConns: 20
    showLog: true`

	write(root_path+"/conf/config.yaml", str)
}

func writeConfig() {
	str := `package config

import (
	"os"
	"strings"

	"context"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"%s/server/utils"
)

var (
	project map[string]string
)

type Config struct {
	Name string
}

func Init(ctx context.Context) error {

	project = ctx.Value("project_info").(map[string]string)

	c := Config{}

	c.initLog()

	cfg := os.Getenv(project["name"] + "_CONFIG")

	if utils.PathExists(cfg) == false {
		log.Panic("缺少配置文件或配置文件不存在")
	}

	c.Name = cfg

	// 初始化配置文件
	if err := c.initConfig(); err != nil {
		return err
	}

	return nil
}

func (c *Config) initConfig() error {
	if c.Name != "" {
		viper.SetConfigFile(c.Name) // 如果指定了配置文件，则解析指定的配置文件
	}
	viper.SetConfigType("yaml")         // 设置配置文件格式为YAML
	viper.AutomaticEnv()                // 读取匹配的环境变量
	viper.SetEnvPrefix(project["name"]) // 读取环境变量的前缀
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	if err := viper.ReadInConfig(); err != nil { // viper解析配置文件
		return err
	}

	return nil
}

func (c *Config) initLog() {
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)

	runMode := viper.GetString("runmode")
	if runMode != "release" {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.ErrorLevel)
	}
}
`
	str = fmt.Sprintf(str, project_path)

	write(root_path+"/server/config/config.go", str)
}

func writeBaseHandler() {
	str := fmt.Sprintf(`package handlers

import (
	"github.com/gin-gonic/gin"

	"%s/server/packages/errno"
	"%s/server/protocols"
	"net/http"
	"strconv"
)

type Base struct {
}

// Success 执行成功
func (this *Base) Success(c *gin.Context, data ...interface{}) {
	var out interface{}
	if len(data) == 0 {
		out = gin.H{}
	} else {
		out = data[0]
	}

	c.JSON(http.StatusOK, protocols.Response{
		Code:       errno.OK.Code,
		Message:    errno.OK.Message,
		Attachment: out,
	})
}

// Failed 执行失败
func (this *Base) Failed(c *gin.Context, code *errno.Errno) {
	debug := code.Debug
	c.JSON(http.StatusOK, protocols.Response{
		Code:       code.Code,
		Debug:      debug,
		Message:    code.Error(),
		Attachment: gin.H{},
	})
}

func (this *Base) QueryInt(c *gin.Context, name string, defaultVal ...int) int {
	v := 0
	if len(defaultVal) > 0 {
		v = defaultVal[0]
	}
	p := c.Query(name)
	if p == "" {
		return v
	}

	i, err := strconv.Atoi(p)
	if err != nil {
		return v
	}
	return i
}

func (this *Base) ParamInt(c *gin.Context, name string, defaultVal ...int) int {
	v := 0
	if len(defaultVal) > 0 {
		v = defaultVal[0]
	}
	p := c.Param(name)
	if p == "" {
		return v
	}

	i, err := strconv.Atoi(p)
	if err != nil {
		return v
	}
	return i
}
`, project_path, project_path)
	write(root_path+"/server/handlers/base.go", str)
}

func writeHomeHandler() {
	str := `package handlers

import (
	"github.com/gin-gonic/gin"
)

type Home struct {
	Base
}

func (this *Home) Check(c *gin.Context) {
	this.Success(c)
}`
	write(root_path+"/server/handlers/home.go", str)
}

func writeConstvars() {
	write(root_path+"/server/packages/constvar/vars.go", `package constvar

const (
	DATE_FORMAT            = "2006-01-02"
	DATETIME_FORMAT        = "2006-01-02 15:04:05"
	DATETIME_SIMPLE_FORMAT = "20060102150405"
)
`)
}

func writeErrnoCode() {
	str := `package errno

var (
	// Common errors
	OK                  = &Errno{Code: 200, Message: "操作成功"}
	InternalServerError = &Errno{Code: 10001, Message: "系统错误"}
	BindError           = &Errno{Code: 10002, Message: "非法的JSON数据"}
	MissParamError      = &Errno{Code: 10003, Message: "缺少参数"}

	DbError       = &Errno{Code: 30100, Message: "数据库错误"}
	NotFoundError = &Errno{Code: 404, Message: "访问地址错误"}

	RecordNotFoundError = &Errno{Code: 50000, Message: "未找到指定记录"}

	NoticeError = &Errno{Code: -1, Message: ""}
)
`
	write(root_path+"/server/packages/errno/code.go", str)
}

func writeErrnoErrno() {
	str := `package errno

type Errno struct {
	Code           int
	Debug          string
	Message        string
	customMessages []string
}

func (this *Errno) Error() string {
	msg := this.Message

	for _, c := range this.customMessages {
		msg += " " + c
	}

	this.customMessages = []string{}
	this.Debug = ""
	return msg
}

func (this *Errno) Add(msg string) *Errno {
	this.customMessages = append(this.customMessages, msg)
	return this
}

func (this *Errno) AddDebug(msg string) *Errno {
	this.Debug = msg
	return this
}
`
	write(root_path+"/server/packages/errno/errno.go", str)
}

func writeHttpClient() {
	write(root_path+"/server/packages/httpclient/requester.go", `package httpclient

import (
	"bytes"
	"errors"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
)

type Requester interface {
	Prepare() error
	GetURI() string
	GetPostData() []byte
	GetHeaders() map[string]string
	GetMethod() string
	Handle(rsp []byte, httpStatus int, err error)
	Error() error
}

//var HttpClient *curl

func New() *curl {
	return &curl{
		requests: make([]Requester, 0),
	}
}

type curl struct {
	requests []Requester
}

func (this *curl) AddRequest(req ...Requester) {
	this.requests = append(this.requests, req...)
}

func (this *curl) Exec() error {

	_exec := func(fn func(req Requester), req1 Requester, wg *sync.WaitGroup) {
		defer func() {
			if err := recover(); err != nil {
				switch err.(type) {
				case error:
					logrus.Errorln("Error: ", err.(error).Error(), " in curl.Exec()")
				}
			}

			wg.Done()
		}()

		fn(req1)
	}

	for _, req := range this.requests {
		if err := req.Prepare(); err != nil {
			return err
		}
	}

	wg := new(sync.WaitGroup)
	for _, req := range this.requests {
		wg.Add(1)
		method := strings.ToUpper(req.GetMethod())
		if method == "GET" {
			go _exec(this.get, req, wg)
		} else if method == "POST" {
			go _exec(this.post, req, wg)
		} else if method == "PUT" {
			go _exec(this.put, req, wg)
		} else if method == "DELETE" {
			go _exec(this.delete, req, wg)
		}
	}

	wg.Wait()
	this.requests = []Requester{}
	return nil
}

func (this *curl) setHeaders(req *http.Request, headers map[string]string) {
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

func (this *curl) do(client *http.Client, req *http.Request) (body []byte, status int, err error) {
	rsp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	defer rsp.Body.Close()
	if rsp.StatusCode != 200 {
		return nil, rsp.StatusCode, errors.New("request failed")
	}
	body, _ = ioutil.ReadAll(rsp.Body)
	return body, 200, nil
}

func (this *curl) get(req Requester) {
	client := &http.Client{}
	req1, _ := http.NewRequest("GET", req.GetURI(), nil)

	this.setHeaders(req1, req.GetHeaders())

	body, status, err := this.do(client, req1)
	req.Handle(body, status, err)
}

func (this *curl) delete(req Requester) {
	client := &http.Client{}
	req1, _ := http.NewRequest("DELETE", req.GetURI(), nil)

	this.setHeaders(req1, req.GetHeaders())

	body, status, err := this.do(client, req1)
	req.Handle(body, status, err)
}

func (this *curl) post(req Requester) {
	client := &http.Client{}
	rawData := bytes.NewBuffer(req.GetPostData())
	req1, _ := http.NewRequest("POST", req.GetURI(), rawData)
	this.setHeaders(req1, req.GetHeaders())
	body, status, err := this.do(client, req1)
	req.Handle(body, status, err)
}

func (this *curl) put(req Requester) {
	client := &http.Client{}
	rawData := bytes.NewBuffer(req.GetPostData())
	req1, _ := http.NewRequest("PUT", req.GetURI(), rawData)
	this.setHeaders(req1, req.GetHeaders())
	body, status, err := this.do(client, req1)
	req.Handle(body, status, err)
}
`)
}

func writeStorageInit() {
	write(root_path+"/server/packages/storage/init.go", `package storage

const (
	DbName = "driver_name"
)

func Init() {
	DB.Init()
	//Mongo.Init()
	//Redis.Init()
	//Searcher.Init()
}
`)
}

func writeMongo() {
	write(root_path+"/server/packages/storage/mongo.go", `package storage

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/mgo.v2"
)

var Mongo *mongo

func init() {
	Mongo = new(mongo)
}

type mongo struct {
	session *mgo.Session
}

func (this *mongo) Init() {
	var err error
	this.session, err = mgo.Dial(viper.GetString("mongo.host"))
	if err != nil {
		logrus.Debugln("Mongodb init failed,err: ", err)
	}

	//mgo.SetDebug(true)
	//mgo.SetLogger(log.New(os.Stderr,"mgo: ",log.LstdFlags))

	this.session.SetMode(mgo.Monotonic, true)
	logrus.Debugln("MongoDB init success.")
}

func (this *mongo) Use(dbName string) *mgo.Database {
	s := this.session.Copy()
	return s.DB(dbName)
}

func (this *mongo) Close() {
	this.session.Close()
}
`)
}

func writeMysql() {
	write(root_path+"/server/packages/storage/mysql.go", `package storage

import (
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/go-xorm/core"
	"github.com/go-xorm/xorm"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"time"
)

type Database struct {
	connections map[string]*xorm.EngineGroup
}

type Source struct {
	dbType string
	addr   string
	user   string
	pswd   string
	name   string
}

func (s *Source) String() string {
	u := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8&interpolateParams=true&parseTime=true&loc=Local",
		//u := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8",
		s.user,
		s.pswd,
		s.addr,
		s.name)
	//"Local")
	return u
}

var DB *Database

func openDB(key, masterUrl string, slaveUrls []string) *xorm.EngineGroup {
	if masterUrl == "" {
		log.Panicf("there has no master source in the dbconfig: %s", key)
	}

	master, err := xorm.NewEngine("mysql", masterUrl)
	if err != nil {
		log.Panic(err)
	}

	slaves := make([]*xorm.Engine, 0)
	if len(slaveUrls) > 0 {
		for _, v := range slaveUrls {
			eg, err := xorm.NewEngine("mysql", v)
			if err != nil {
				log.Panic(err)
			}
			slaves = append(slaves, eg)
		}
	}

	group, err := xorm.NewEngineGroup(master, slaves)
	if err != nil {
		log.Panic(err)
	}

	setupDB(key, group)

	return group
}

func setupDB(key string, group *xorm.EngineGroup) {
	if viper.GetBool(fmt.Sprintf("db.%s.showLog", key)) == true {
		group.ShowSQL(true)
		group.Logger().SetLevel(core.LOG_INFO)
	} else {
		group.ShowSQL(false)
	}

	var (
		maxIdleConns int
		maxOpenConns int
	)

	maxIdleConns = viper.GetInt(fmt.Sprintf("db.%s.idleConns", key))
	maxOpenConns = viper.GetInt(fmt.Sprintf("db.%s.openConns", key))

	if maxOpenConns == 0 {
		maxOpenConns = 40
	}

	if maxIdleConns == 0 {
		maxIdleConns = 20
	}

	local, _ := time.LoadLocation("Asia/Shanghai")
	group.DatabaseTZ = local
	group.TZLocation = local
	group.SetMaxOpenConns(maxOpenConns)
	group.SetMaxIdleConns(maxIdleConns)
	//group.SetConnMaxLifetime(300 * time.Second)

	if err := group.Ping(); err != nil {
		log.Errorf("Db: %s connected failed", key)
	} else {
		log.Infof("Db: %s connected success", key)
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				group.Ping()
			}
		}
	}()
}

func (db *Database) Init() {
	DB = &Database{
		connections: make(map[string]*xorm.EngineGroup),
	}

	dbConfigs := viper.GetStringMap("db")
	if len(dbConfigs) < 1 {
		panic("db config is empty...")
	}

	for key, _ := range dbConfigs {
		var (
			interfaceTemp interface{}
		)
		interfaceTemp = viper.Get(fmt.Sprintf("db.%s.master", key))
		if interfaceTemp == nil {
			log.Panicf("dbconfig: %s missing master conf", key)
		}

		masterConfig := interfaceTemp.(map[string]interface{})
		s := &Source{
			dbType: "mysql",
			addr:   masterConfig["host"].(string),
			user:   masterConfig["user"].(string),
			name:   masterConfig["name"].(string),
			pswd:   masterConfig["pswd"].(string),
		}
		masterSource := s.String()

		slaveSources := make([]string, 0)
		interfaceTemp = viper.Get(fmt.Sprintf("db.%s.slaves", key))
		if interfaceTemp != nil {

			switch interfaceTemp.(type) {
			case []interface{}:
			default:
				log.Panicf("dbConfig: %s slave config is not valid", key)
			}

			slaveConfigs := interfaceTemp.([]interface{})
			for _, v := range slaveConfigs {
				switch v.(type) {
				case map[interface{}]interface{}:
				default:
					log.Panicf("dbConfig: %s slave config is not valid", key)
				}

				vv := v.(map[interface{}]interface{})

				s := &Source{dbType: "mysql"}
				for k, vvv := range vv {
					switch k.(string) {
					case "host":
						s.addr = vvv.(string)
					case "user":
						s.user = vvv.(string)
					case "name":
						s.name = vvv.(string)
					case "pswd":
						s.pswd = vvv.(string)
					}
				}
				slaveSources = append(slaveSources, s.String())
			}
		}
		DB.connections[key] = openDB(key, masterSource, slaveSources)
	}
}

func (db *Database) Close() {
	for _, c := range DB.connections {
		c.Close()
	}
}

func (db *Database) Use(dbKey string) *xorm.EngineGroup {
	if d, ok := DB.connections[dbKey]; ok {
		return d
	} else {
		return nil
	}
}
`)
}

func writeRedis() {
	write(root_path+"/server/packages/storage/redis.go", `package storage

import (
	"github.com/go-redis/redis"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var Redis *_redis

func init() {
	Redis = new(_redis)
}

type _redis struct {
	client *redis.Client
}

func (this *_redis) Init() {
	this.client = redis.NewClient(&redis.Options{
		Addr:     viper.GetString("redis.addr"),
		Password: viper.GetString("redis.password"), // no password set
		DB:       viper.GetInt("redis.db"),          // use default DB
	})

	_, err := this.client.Ping().Result()
	if err != nil {
		logrus.Fatalln("Redis connecte failed.")
	} else {
		logrus.Debugln("Redis inited.")
	}
}

func (this *_redis) Client() *redis.Client {
	return this.client
}
`)
}

func writeResponse() {
	str := `package protocols
	
type Response struct {
	Code       int         %sjson:"code"%s
	Message    string      %sjson:"message"%s
	Debug      string      %sjson:"debug"%s
	Attachment interface{} %sjson:"result"%s
}`
	write(root_path+"/server/protocols/response.go", fmt.Sprintf(str, "`", "`", "`", "`", "`", "`", "`", "`"))
}

func writeConsul() {
	str := `package registry

import (
	"context"
	"crypto/tls"
	"fmt"
	consul "github.com/hashicorp/consul/api"
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

type Consul struct {
	Address   string
	Client    *consul.Client
	Timeout   time.Duration
	Intval    time.Duration
	Secure    bool
	TLSConfig *tls.Config

	// Other options for implementations of the interface
	// can be stored in a context
	Context context.Context

	// connect enabled
	connect bool

	queryOptions *consul.QueryOptions

	sync.Mutex
	//register map[string]uint64
	// lastChecked tracks when a node was last checked as existing in Consul
	lastChecked time.Time
}

func NewRegistry() *Consul {
	config := consul.DefaultConfig()
	client, err := consul.NewClient(config)
	if err != nil {
		log.Panic(err)
	}

	return &Consul{
		Timeout: 3 * time.Second,
		Intval:  3 * time.Second,
		Client:  client,
	}
}

func (this *Consul) Register(node *Node) error {

	// @todo tags 是针对 Node 还是针对 service ?
	tags := this.encodeMetadata(node.Metadata)
	asr := &consul.AgentServiceRegistration{
		ID:      node.Id,
		Name:    node.Name,
		Tags:    tags,
		Port:    node.Port,
		Address: node.Address,
		Check: &consul.AgentServiceCheck{
			HTTP:                           fmt.Sprintf("http://%s:%d%s", node.Address, node.Port, "/check"),
			Timeout:                        this.Timeout.String(),
			Interval:                       this.Intval.String(),
			DeregisterCriticalServiceAfter: "30s",
		},
	}

	if this.connect {
		asr.Connect = &consul.AgentServiceConnect{
			Native: true,
		}
	}

	if err := this.Client.Agent().ServiceRegister(asr); err != nil {
		return err
	}

	this.Lock()
	this.lastChecked = time.Now()
	this.Unlock()

	return nil
}

func (this *Consul) Degister(node *Node) error {
	this.Lock()
	err := this.Client.Agent().ServiceDeregister(node.Id)
	this.Unlock()
	return err
}

func (this *Consul) encodeMetadata(md map[string]string) []string {
	var tags []string
	for k, v := range md {
		tags = append(tags, fmt.Sprintf("%s:%s", k, v))
	}

	return tags
}`
	write(root_path+"/server/registry/consul.go", str)
}

func writeNode() {
	str := fmt.Sprintf(`package registry

import (
	"context"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"%s/server/utils"
	"net"
	"os"
)

type Node struct {
	Id       string            
	Name     string            
	Address  string            
	Port     int               
	Metadata map[string]string 
}

func InitNode(ctx context.Context) *Node {

	project := ctx.Value("project_info").(map[string]string)

	host, _ := os.Hostname()
	uuid := utils.UUID()

	node := &Node{
		Id:   uuid,
		Name: project["name"],
		Metadata: map[string]string{
			"host": host,
		},
	}

	node.Address = viper.GetString("server.addr")
	port := viper.GetInt("server.port")

	if node.Address == "" {
		ips, err := utils.GetIP()
		if err != nil {
			log.Panic(err)
		}

		node.Address = ips[0]
	}

	if port == 0 {
		l, _ := net.Listen("tcp", ":0")
		port = l.Addr().(*net.TCPAddr).Port
		l.Close()
	}

	node.Port = port

	return node
}
`, project_path)
	write(root_path+"/server/registry/node.go", str)
}

func writeRouter() {
	str := fmt.Sprintf(`package router

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"%s/server/handlers"
	"%s/server/protocols"
	"%s/server/router/middleware"
)

func Load(g *gin.Engine) *gin.Engine {

	// 防止 Panic 把进程干死
	g.Use(gin.Recovery(), middleware.Logger())
	g.Use(cors.New(cors.Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"POST", "GET", "PUT", "DELETE"},
		AllowHeaders:    []string{"Access-Control-Allow-Headers:DNT,X-Mx-ReqToken,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Authorization,x-token"},
	}))

	// 默认404
	g.NoRoute(func(context *gin.Context) {
		context.JSON(404, protocols.Response{
			Code:    404,
			Message: "Not Found",
		})
	})

	g.GET("/check", new(handlers.Home).Check)

	return g

}`, project_path, project_path, project_path)
	write(root_path+"/server/router/router.go", str)
}

func writeMiddlewareAuthorize() {
	str := `package middleware

import (
	"github.com/gin-gonic/gin"
)

func Authorize(context *gin.Context) {
	context.Next()
}
`
	write(root_path+"/server/router/middleware/authorize.go", str)
}

func writeMiddlewareLogger() {
	str := `package middleware

import (
	"fmt"
	"io"
	"time"

	"bytes"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"io/ioutil"
)

var (
	green   = string([]byte{27, 91, 57, 55, 59, 52, 50, 109})
	white   = string([]byte{27, 91, 57, 48, 59, 52, 55, 109})
	yellow  = string([]byte{27, 91, 57, 55, 59, 52, 51, 109})
	red     = string([]byte{27, 91, 57, 55, 59, 52, 49, 109})
	blue    = string([]byte{27, 91, 57, 55, 59, 52, 52, 109})
	magenta = string([]byte{27, 91, 57, 55, 59, 52, 53, 109})
	cyan    = string([]byte{27, 91, 57, 55, 59, 52, 54, 109})
	reset   = string([]byte{27, 91, 48, 109})
)

type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func Logger() gin.HandlerFunc {
	return LoggerWithWriter(gin.DefaultWriter)
}

func LoggerWithWriter(out io.Writer) gin.HandlerFunc {
	isTerm := true

	return func(c *gin.Context) {
		// Start timer
		start := time.Now()
		path := c.Request.URL.Path

		if c.Request.URL.RawQuery != "" {
			path += "?" + c.Request.URL.RawQuery
		}

		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = ioutil.ReadAll(c.Request.Body)
		}

		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		blw := &bodyLogWriter{
			body:           bytes.NewBufferString(""),
			ResponseWriter: c.Writer,
		}
		c.Writer = blw

		// Process request
		c.Next()

		end := time.Now()
		latency := end.Sub(start)

		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		var statusColor, methodColor string
		if isTerm {
			statusColor = colorForStatus(statusCode)
			methodColor = colorForMethod(method)
		}
		comment := c.Errors.ByType(gin.ErrorTypePrivate).String()

		fmt.Fprintf(out, "[GIN] %v |%s %3d %s| %13v | %15s |%s  %s %-7s %s\n%s",
			end.Format("2006/01/02 - 15:04:05"),
			statusColor, statusCode, reset,
			latency,
			clientIP,
			methodColor, method, reset,
			path,
			comment,
		)
		logrus.Infoln("Request: ", string(bodyBytes[:]))
		logrus.Infoln("Response: ", string(blw.body.Bytes()[:len(blw.body.Bytes())]))
		fmt.Println("")
	}
}

func colorForStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return green
	case code >= 300 && code < 400:
		return white
	case code >= 400 && code < 500:
		return yellow
	default:
		return red
	}
}

func colorForMethod(method string) string {
	switch method {
	case "GET":
		return blue
	case "POST":
		return cyan
	case "PUT":
		return yellow
	case "DELETE":
		return red
	case "PATCH":
		return green
	case "HEAD":
		return magenta
	case "OPTIONS":
		return white
	default:
		return reset
	}
}
`
	write(root_path+"/server/router/middleware/logger.go", str)
}

func writeUtilsTools() {
	str := `package utils


import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"github.com/satori/go.uuid"
	"io"
	"os"
)

func EncodeMD5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	cipherStr := h.Sum(nil)
	return hex.EncodeToString(cipherStr)
}

func FileMd5(filePath string) (string, error) {
	//Initialize variable returnMD5String now in case an error has to be returned
	var returnMD5String string

	//Open the passed argument and check for any error
	file, err := os.Open(filePath)
	if err != nil {
		return returnMD5String, err
	}

	//Tell the program to call the following function when the current function returns
	defer file.Close()

	//Open a new hash interface to write to
	hash := md5.New()

	//Copy the file in the hash interface and check for any error
	if _, err := io.Copy(hash, file); err != nil {
		return returnMD5String, err
	}

	//Get the 16 bytes hash
	hashInBytes := hash.Sum(nil)[:16]

	//Convert the bytes to a string
	returnMD5String = hex.EncodeToString(hashInBytes)

	return returnMD5String, nil

}

func EncodeSha1(str string) string {
	s := sha1.New()
	s.Write([]byte(str))
	bs := s.Sum(nil)

	return hex.EncodeToString(bs)
}

func EncodeBase64(data []byte) string {
	encodeString := base64.StdEncoding.EncodeToString(data)
	return encodeString
}

func PathExists(path string) bool {
	if path == "" {
		return false
	}

	_, err := os.Stat(path)
	if err == nil {
		return true
	}

	if os.IsNotExist(err) {
		return false
	}

	return false
}

func Mkdir(path string) error {
	exist := PathExists(path)
	if !exist {
		err := os.MkdirAll(path, os.ModePerm)
		return err
	}

	return nil
}

func GetIP() ([]string, error) {
	var ips []string
	addrs, err := net.InterfaceAddrs()

	if err != nil {
		return ips, err
	}

	for _, address := range addrs {
		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}

	return ips, nil
}

func Ip2num(ip string) int {
	canSplit := func(c rune) bool { return c == '.' }
	lisit := strings.FieldsFunc(ip, canSplit) //[58 215 20 30]
	//fmt.Println(lisit)
	ip1_str_int, _ := strconv.Atoi(lisit[0])
	ip2_str_int, _ := strconv.Atoi(lisit[1])
	ip3_str_int, _ := strconv.Atoi(lisit[2])
	ip4_str_int, _ := strconv.Atoi(lisit[3])
	return ip1_str_int<<24 | ip2_str_int<<16 | ip3_str_int<<8 | ip4_str_int
}

func Num2ip(num int) string {
	ip1_int := (num & 0xff000000) >> 24
	ip2_int := (num & 0x00ff0000) >> 16
	ip3_int := (num & 0x0000ff00) >> 8
	ip4_int := num & 0x000000ff
	//fmt.Println(ip1_int)
	data := fmt.Sprintf("%d.%d.%d.%d", ip1_int, ip2_int, ip3_int, ip4_int)
	return data
}

func Date() string {
	return TimeFormat(time.Now())
}

func TimeFormat(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}

func GreenwichToDate(date string) string {
	pos := strings.IndexAny(date, "+")
	if pos != -1 {
		date = date[:pos]
	}

	pos = strings.IndexAny(date, "T")
	if pos != -1 {
		date = strings.Replace(date, "T", " ", pos)
	}
	return date
}

func UUID() string {
	id, _ := uuid.NewV4()
	return strings.Replace(id.String(), "-", "", -1)
}

func JsonEncode(o interface{}) (ret []byte, err error) {
	ret, err = json.Marshal(o)
	return
}
`
	write(root_path+"/server/utils/tools.go", str)
}

func writeServer() {
	str := fmt.Sprintf(`package server

import (
	"net/http"
	"strconv"

	"%s/server/registry"
	"%s/server/router"

	"context"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"%s/server/packages/storage"
)

var (
	node     *registry.Node
	Registry *registry.Consul
)

func Init(ctx context.Context) {
	node = registry.InitNode(ctx)
	Registry = registry.NewRegistry()
	storage.Init()
}

func Start() error {

	g := gin.New()

	runmode := viper.GetString("server.runmode")
	if runmode == "" {
		runmode = "debug"
	}
	gin.SetMode(runmode)

	router.Load(g)

	go func() {
		address := node.Address + ":" + strconv.Itoa(node.Port)
		log.Infoln("http server listen on", address, ":", node.Port)
		err := http.ListenAndServe(address, g).Error()
		if err != "" {
			log.Panic(err)
		}
	}()

	return nil
}

func Stop() error {
	return nil
}

func Register() error {
	if viper.GetBool("consul") {
		return Registry.Register(node)
	}
	return nil
}

func Deregister() error {
	if viper.GetBool("consul") {
		return Registry.Degister(node)
	}
	return nil
}
`, project_path, project_path,project_path)

	write(root_path+"/server/server.go", str)
}

func writeMakefile() {
	str := `all: build

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./bin/main -tags static -ldflags -v main.go

clean:
	rm  -r ./bin/*

gotool:
	gofmt -w .

help:
	@echo "make - compile the source code"
	@echo "make clean - remove binary file and vim swp files"
	@echo "make gotool - run go tool 'fmt' and 'vet'"

.PHONY: clean gotool help...
`
	write(root_path+"/Makefile", str)
}
