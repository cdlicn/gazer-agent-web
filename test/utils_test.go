package test

import (
	"agent/utils"
	"fmt"
	"os"
	"testing"
)

func TestSha256(t *testing.T) {
	user, err := utils.EncryptUser("admin", "123456")
	if err != nil {
		panic(err)
	}
	fmt.Println(user)
	file, err := os.OpenFile("../credit.enc", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	n, err := file.Write(user[:])
	if err != nil {
		panic(err)
	}
	fmt.Println(n)
}

func TestVerifyUser(t *testing.T) {
	readFile, err := os.ReadFile("../credit.enc")
	if err != nil {
		panic(err)
	}
	fmt.Println(readFile)
	err = utils.VerifyUser("aaadmin", "123456", readFile)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("true")
}

func TestJwt(t *testing.T) {
	//token, err := service.GenerateToken("admin", "admin")
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println(token)
}

func TestRead(t *testing.T) {
	file, err := os.ReadFile("./aaa.txt")
	if err != nil {
		panic(err)
	}
	fmt.Println(len(file) == 0)
}
