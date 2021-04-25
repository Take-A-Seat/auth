package main

import (
	"context"
	"fmt"
	"github.com/Take-A-Seat/auth/validatorAuth"
	"github.com/Take-A-Seat/storage"
	jwt "github.com/appleboy/gin-jwt/v2"
	jwtGo "github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/twinj/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
	"net/http"
	"os"
	"time"
)

var mongoHost = "takeaseat.knilq.mongodb.net"
var mongoUser = "admin"
var mongoPass = "p4r0l4"
var mongoDatabase = "TakeASeat"

func isAuthenticated(c *gin.Context) {
	claims := jwt.ExtractClaims(c)

	client, err := storage.ConnectToDatabase(mongoUser, mongoPass, mongoHost, mongoDatabase)
	if err != nil {
		storage.DisconnectFromDatabase(client)
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	userObjectId, _ := primitive.ObjectIDFromHex(fmt.Sprintf("%s", claims["UserId"]))
	usersCollection := client.Database(dbName).Collection("users")
	var user struct {
		Role string `bson:"role"`
	}
	err = usersCollection.FindOne(context.Background(), bson.M{"_id": userObjectId}).Decode(&user)
	if err != nil {
		storage.DisconnectFromDatabase(client)
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"UserId":    claims["UserId"],
		"Email":     claims["Email"],
		"firstName": claims["FirstName"],
		"lastName":  claims["LastName"],
		"role":      user.Role,
	})

	storage.DisconnectFromDatabase(client)
	return
}
func createRefreshToken(c *gin.Context) (string, error) {
	data, err := authorize(c)
	if err != nil {
		return "", err
	}

	// we claim the data from the authorization (userId, email, first name and last name and after that
	// we create the refresh token using them.
	claims := myPayload(data)

	refreshUuid := uuid.NewV4().String()
	refreshExpires := time.Now().Add(time.Hour * 24 * 7).Unix()
	rtClaims := jwtGo.MapClaims{}
	rtClaims["refresh_uuid"] = refreshUuid
	rtClaims["UserId"] = claims["UserId"]
	rtClaims["exp"] = refreshExpires
	rtClaims["Email"] = claims["Email"]
	rtClaims["FirstName"] = claims["FirstName"]
	rtClaims["LastName"] = claims["LastName"]
	rt := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, rtClaims)
	secretKey := []byte("memgNN8gNWewfQlVeQOINrUdlaaahtbBLzSCDcvczcE2sydLXaNZr1cgs9TLNen")

	RefreshToken, err := rt.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return RefreshToken, nil
}
func Login(c *gin.Context, status int, token string, expire time.Time) {
	// In this function we receive a context, a status, the auth token and the expiration time.
	// Below we create the refresh token and then we send via gin context.
	if status != 200 {
		c.JSON(status, gin.H{"message": "Error!"})
		return
	}

	refreshToken, err := createRefreshToken(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
		return
	}

	successJson := gin.H{
		"auth_token":    token,
		"expire":        expire.String(),
		"refresh_token": refreshToken,
	}

	c.JSON(http.StatusOK, successJson)
	return
}

type customClaims struct {
	UserId    interface{}
	Email     interface{}
	FirstName interface{}
	LastName  interface{}
}

func createToken(claims customClaims, isRefreshToken bool) (string, error) {
	uuid := uuid.NewV4().String()
	expires := time.Now().Add(time.Hour).Unix()
	if isRefreshToken {
		expires = time.Now().Add(time.Hour * 24 * 7).Unix()
	}
	newClaims := jwtGo.MapClaims{}
	newClaims["refresh_uuid"] = uuid
	newClaims["UserId"] = claims.UserId
	newClaims["exp"] = expires
	newClaims["Email"] = claims.Email
	newClaims["FirstName"] = claims.FirstName
	newClaims["LastName"] = claims.LastName

	t := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, newClaims)
	secretKey := []byte("secret key")

	token, err := t.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return token, nil
}

func handleRefreshToken(c *gin.Context) {
	mapToken := map[string]string{}
	var newRefreshToken string
	var authToken string

	if err := c.ShouldBindJSON(&mapToken); err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}

	// after we extract the refresh token from the request's body we verify if it's not expired.
	// if it's expired we finish the execution of the function and we return 401 status.
	// if it's not expired and it's a valid refresh token we create a new auth token and a new refresh token and send them via endpoint.

	refreshToken := mapToken["refresh_token"]
	fmt.Println("map", mapToken)
	token, err := jwtGo.Parse(refreshToken, func(token *jwtGo.Token) (interface{}, error) {
		fmt.Println(refreshToken)
		if _, ok := token.Method.(*jwtGo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte("secret key"), nil
	})

	if err != nil {
		fmt.Println("expirat")
		c.JSON(http.StatusUnauthorized, "Refresh token expired")
		return
	}
	if _, ok := token.Claims.(jwtGo.Claims); !ok && !token.Valid {
		c.JSON(http.StatusUnauthorized, err)
		return
	}

	authExpires := time.Now().Add(time.Hour)
	claims, ok := token.Claims.(jwtGo.MapClaims)
	if ok && token.Valid {
		var claimsData customClaims
		claimsData.FirstName = claims["FirstName"]
		claimsData.Email = claims["Email"]
		claimsData.UserId = claims["UserId"]
		claimsData.LastName = claims["LastName"]
		authToken, err = createToken(claimsData, false)
		if err != nil {
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}

		newRefreshToken, err = createToken(claimsData, true)
		if err != nil {
			c.JSON(http.StatusBadRequest, err.Error())
			return
		}
	}

	successJson := gin.H{
		"auth_token":    authToken,
		"expire":        authExpires.String(),
		"refresh_token": newRefreshToken,
	}

	c.JSON(http.StatusOK, successJson)
	return
}

var Port = "9100"
var dbName = "TakeASeat"
var apiUrl = "https://api.takeaseat.site"

func main() {
	port := os.Getenv("AUTH_PORT")
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if port == "" {
		port = Port
	}
	// For handling auth we use gin-jwt package. Below we initiate the package and we attribute it to authMiddleware variable.
	// Among others, the package needs some methods to help to handle the authentication. The function witch is attributed to
	// LoginResponse (Login) is called when the auth is successfully done.
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:           "TakeASeat",
		Key:             []byte("memgNN8gNWewfQlVeQOINrUdlaaahtbBLzSCDcvczcE2sydLXaNZr1cgs9TLNen"),
		Timeout:         time.Hour,
		MaxRefresh:      time.Hour,
		IdentityKey:     validatorAuth.IdentityKey,
		PayloadFunc:     myPayload,
		IdentityHandler: myIdentity,
		Authenticator:   authorize,
		Authorizator:    authorizator,
		Unauthorized:    unauthorized,
		TokenLookup:     "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:   "Bearer",
		TimeFunc:        time.Now,
		LoginResponse:   Login,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"PUT", "PATCH", "DELETE", "GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accepts", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	r.POST("/auth/login", authMiddleware.LoginHandler)

	r.NoRoute(authMiddleware.MiddlewareFunc(), noRoute)

	auth := r.Group("/auth")
	auth.POST("/refresh_token", func(c *gin.Context) {
		handleRefreshToken(c)
	})

	auth.Use(authMiddleware.MiddlewareFunc())
	{
		fmt.Println("fmmm")
		auth.GET("/isAuthenticated", isAuthenticated)
	}

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}

}
