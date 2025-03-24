package common

import (
	"agent/etcd"
	"agent/utils"
	"github.com/golang-jwt/jwt/v4"
	"gopkg.in/ini.v1"
)

const (
	EncPath = "credit.enc"
	JwtKey  = "https://github.com/cdlicn/gazer"
)

var (
	ConfigObj Config
	Ip        string
)

type User struct {
	Username string
	Password string
}

type JwtClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type Config struct {
	EtcdConfig `ini:"etcd"`
}

type EtcdConfig struct {
	Address string `ini:"address"`
}

func Init() {
	// Load config
	err := ini.MapTo(&ConfigObj, "conf/config.ini")
	if err != nil {
		panic(err)
	}

	// Get ip
	Ip, err = utils.GetOutboundIp()
	if err != nil {
		panic(err)
	}

	// Init etcd
	err = etcd.Init(ConfigObj.Address)
	if err != nil {
		panic(err)
	}
}
