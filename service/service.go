package service

import (
	"agent/common"
	"agent/etcd"
	"agent/utils"
	"github.com/golang-jwt/jwt/v4"
	//"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"os"
)

// generateToken 生成Token
func generateToken(username string) (string, error) {
	claims := &common.JwtClaims{
		Username: username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(common.JwtKey))
}

// Login 登录
func Login(c *gin.Context) {
	username := c.PostForm("username")
	if username == "" {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "username is empty",
		})
		return
	}

	password := c.PostForm("password")
	if password == "" {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "password is empty",
		})
		return
	}

	// 读取credit.enc文件
	readFile, err := os.ReadFile(common.EncPath)
	if err != nil {
		// 文件不存在，创建文件
		_, err := os.Create(common.EncPath)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": -1,
				"msg":  "failed to load credit",
			})
			return
		}
	}

	if err != nil || len(readFile) == 0 {
		// 默认用户名密码
		if username == "admin" && password == "admin" {
			// 生成token
			token, err := generateToken(username)
			if err != nil {
				c.JSON(http.StatusOK, gin.H{
					"code": -1,
					"msg":  "failed to login",
				})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"code":  0,
				"msg":   "success",
				"token": token,
			})
			return
		} else {
			c.JSON(http.StatusOK, gin.H{
				"code": -1,
				"msg":  "failed to login",
			})
			return
		}
	}

	// 验证用户名密码
	err = utils.VerifyUser(username, password, readFile)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "failed to login",
		})
		return
	}
	// 生成token
	token, err := generateToken(username)
	c.JSON(http.StatusOK, gin.H{
		"code":  0,
		"msg":   "success",
		"token": token,
	})
}

func List(c *gin.Context) {
	list, err := etcd.List(common.Ip)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "failed to get list",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "success",
		"data": list,
	})
}

func Update(c *gin.Context) {
	topic := c.PostForm("topic")
	if topic == "" {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "topic is empty",
		})
		return
	}
	path := c.PostForm("path")
	if path == "" {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "path is empty",
		})
		return
	}

	path, b := utils.IsFileExist(path)
	if !b {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "file is not exist",
		})
		return
	}

	err := etcd.Update(common.Ip, topic, path)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  err.Error(),
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "success",
	})
}

func Delete(c *gin.Context) {
	topic := c.Param("topic")
	if topic == "" {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "topic is empty",
		})
		return
	}

	err := etcd.Delete(common.Ip, topic)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "failed to delete",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "success",
	})
}

func Add(c *gin.Context) {
	topic := c.PostForm("topic")
	if topic == "" {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "topic is empty",
		})
		return
	}

	path := c.PostForm("path")
	if path == "" {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "path is empty",
		})
		return
	}

	err := etcd.Add(common.Ip, topic, path)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "failed to add",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "success",
	})
}

func ChangePwd(c *gin.Context) {
	oldPassword := c.PostForm("oldPassword")
	if oldPassword == "" {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "old password is empty",
		})
		return
	}

	newPassword := c.PostForm("newPassword")
	if newPassword == "" {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "new password is empty",
		})
		return
	}

	readFile, err := os.ReadFile(common.EncPath)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "failed to change password",
		})
		return
	}

	if len(readFile) == 0 {
		if oldPassword != "admin" {
			c.JSON(http.StatusOK, gin.H{
				"code": -1,
				"msg":  "failed to change password",
			})
			return
		}
		// 生成新密码
		code, err := utils.EncryptUser("admin", newPassword)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": -1,
				"msg":  "failed to change password",
			})
			return
		}
		// 写入新密码
		err = os.WriteFile(common.EncPath, code, 0644)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": -1,
				"msg":  "failed to change password",
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"code": 0,
			"msg":  "success",
		})
		return
	}

	// 验证旧密码
	err = utils.VerifyUser("admin", oldPassword, readFile)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "failed to change password",
		})
		return
	}

	// 生成新密码
	code, err := utils.EncryptUser("admin", newPassword)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "failed to change password",
		})
		return
	}
	// 写入新密码
	err = os.WriteFile(common.EncPath, code, 0644)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": -1,
			"msg":  "failed to change password",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"msg":  "success",
	})

}
