package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Take-A-Seat/auth/validatorAuth"
	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"log"
	"net/http"
)

type login struct {
	Email    string `form:"email" json:"email" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

func authorize(c *gin.Context) (interface{}, error) {
	var loginVals login
	if err := c.ShouldBind(&loginVals); err != nil {
		return "", jwt.ErrMissingLoginValues
	}
	userEmail := loginVals.Email
	password := loginVals.Password
	apiURL := apiUrl+ "/users/validateUser"
	fmt.Println("apiURL",apiURL)
	var jsonStr = []byte(`{"email":"` + userEmail + `","password":"` + password + `"}`)
	userRequest, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, jwt.ErrFailedAuthentication
	}

	apiClient := &http.Client{}
	validateUserResponse, getErr := apiClient.Do(userRequest)
	if getErr != nil {
		return nil, jwt.ErrFailedAuthentication
	}

	if validateUserResponse.Body != nil {
		defer validateUserResponse.Body.Close()
	}

	userData, userErr := ioutil.ReadAll(validateUserResponse.Body)
	if userErr != nil {
		return nil, jwt.ErrFailedAuthentication
	}

	var result map[string]interface{}
	err = json.Unmarshal(userData, &result)
	if err != nil {
		return nil, jwt.ErrFailedAuthentication
	}

fmt.Println("result",result)
	return &validatorAuth.User{
		UserId:    fmt.Sprintf("%s", result["id"]),
		Email:     userEmail,
		LastName:  fmt.Sprintf("%s", result["lastName"]),
		FirstName: fmt.Sprintf("%s", result["firstName"]),
	}, nil

}

func authorizator(data interface{}, c *gin.Context) bool {

	fmt.Println("Authorizator", data)
	if v, ok := data.(*customClaims); ok && v.UserId != "" {
		return true
	}

	return false
}

func unauthorized(c *gin.Context, code int, message string) {
	c.JSON(code, gin.H{
		"code":    code,
		"message": message,
	})
}

func myPayload(data interface{}) jwt.MapClaims {
	if v, ok := data.(*validatorAuth.User); ok {

		return jwt.MapClaims{
			"UserId":    v.UserId,
			"Email":     v.Email,
			"FirstName": v.FirstName,
			"LastName":  v.LastName,
		}
	}
	return jwt.MapClaims{}
}

func myIdentity(c *gin.Context) interface{} {
	claims := jwt.ExtractClaims(c)

	fmt.Println("myidentity", claims)
	return &customClaims{
		UserId:    claims["UserId"],
		Email:     claims["Email"],
		FirstName: claims["FirstName"],
		LastName:  claims["LastName"],
	}
}

func noRoute(c *gin.Context) {
	claims := jwt.ExtractClaims(c)
	log.Printf("NoRoute claims: %#v\n", claims)
	c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "message": "Page not found"})
}
