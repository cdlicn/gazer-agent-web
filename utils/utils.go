package utils

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type user struct {
	Username string
	Password string
}

// EncryptUser 用户加密
func EncryptUser(username, password string) (code []byte, err error) {
	u := user{Username: username, Password: password}
	jsonData, err := json.Marshal(u)
	if err != nil {
		return code, err
	}
	code, err = bcrypt.GenerateFromPassword(jsonData, bcrypt.DefaultCost)
	return code, nil
}

// VerifyUser 用户验证
func VerifyUser(username, password string, code []byte) error {
	u := user{Username: username, Password: password}
	jsonData, err := json.Marshal(u)
	if err != nil {
		return err
	}
	err = bcrypt.CompareHashAndPassword(code, jsonData)
	return err
}

// GetOutboundIp 获取本机Ip
func GetOutboundIp() (ip string, err error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return ip, fmt.Errorf("failed to get ip.")
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	ip = strings.Split(localAddr.IP.String(), ":")[0]
	return ip, nil
}

// IsFileExist 检查path是否存在 (return 绝对路径, 是否存在)
func IsFileExist(path string) (string, bool) {
	// 判断是否为绝对路径
	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return "", false
		}
		path = absPath
	}
	// 获取当前文件地址
	_, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	return path, true
}
