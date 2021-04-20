package main

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"net/http"
)

type User struct {
	UserId    string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

var IdentityKey = "id"

// apiURL Example:  http://127.0.0.1:9100/auth/isAuthenticated

func AuthMiddleware(apiURL string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		token = token[7:]
		apiClient := &http.Client{}
		validateUserRequest, err := http.NewRequest("GET", apiURL, nil)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{})
		}
		validateUserRequest.Header.Set("Authorization", "Bearer "+token)
		validateUserResponse, getErr := apiClient.Do(validateUserRequest)
		if getErr != nil {
			c.JSON(http.StatusForbidden, gin.H{})
		}

		if validateUserResponse.Body != nil {
			defer validateUserResponse.Body.Close()
		}

		userData, userErr := ioutil.ReadAll(validateUserResponse.Body)
		if userErr != nil {
			c.JSON(http.StatusForbidden, gin.H{})
		}

		authenticatedUser := User{}
		jsonErr := json.Unmarshal(userData, &authenticatedUser)
		if jsonErr != nil {
			c.JSON(http.StatusForbidden, gin.H{})
		}

		fmt.Println(authenticatedUser.Email)

	}
}
