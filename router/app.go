package router

import (
	"agent/middlewares"
	"agent/service"
	"github.com/gin-gonic/gin"
)

func Router() *gin.Engine {
	r := gin.Default()

	api := r.Group("/api")

	api.POST("/login", service.Login)

	index := api.Group("", middlewares.CheckJwt())

	{
		index.GET("/list", service.List)
		index.PUT("/update", service.Update)
		index.DELETE("/delete/:topic", service.Delete)
		index.POST("/add", service.Add)
		index.PUT("/change_password", service.ChangePwd)
	}

	return r
}
