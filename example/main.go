package main

import (
	"github.com/ProAdminServ/auth/auth"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"os"
)

func dummyHandler(c *gin.Context) {
	c.JSON(http.StatusOK, nil)
}
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9005"
	}
	gin.SetMode(gin.ReleaseMode)

	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"PUT", "PATCH", "DELETE", "GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accepts", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	router.Use(auth.AuthMiddleware("http://127.0.0.1:9100/auth/isAuthenticated"))
	dummy := router.Group("/dummy")
	{
		dummy.GET("/", dummyHandler)
	}

	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatal(err)
	}
}
