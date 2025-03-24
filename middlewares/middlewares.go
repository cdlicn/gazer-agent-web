package middlewares

import (
	"agent/common"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"net/http"
)

func CheckJwt() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code": -1,
				"msg":  "token is empty",
			})
			c.Abort()
			return
		}
		claims := &common.JwtClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(common.JwtKey), nil
		})

		if err != nil {
			fmt.Println(err)
			if err == jwt.ErrSignatureInvalid {
				c.JSON(http.StatusUnauthorized, gin.H{
					"code": -1,
					"msg":  "invalid  toke signature",
				})
				c.Abort()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{
				"code": -1,
				"msg":  "bac request",
			})
			c.Abort()
			return
		}

		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code": -1,
				"msg":  "invalid token",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
