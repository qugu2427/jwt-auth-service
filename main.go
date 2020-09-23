package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type user struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Email    string             `bson:"email"`
	Password string             `bson:"password"`
	Verified bool               `bson:"verified"`
	Auth     int64              `bson:"auth"`
}

var tokenKey string
var usersCollection *mongo.Collection

func main() {
	// Load in env vars from secrets.env
	err := godotenv.Load("secrets.env")
	if err != nil {
		log.Print("could not find secrets.env")
	}
	uri, exists := os.LookupEnv("URI")
	if !exists {
		log.Fatal("could not find URI in secrets.env")
	}
	port, exists := os.LookupEnv("PORT")
	if !exists {
		log.Fatal("could not find PORT in secrets.env")
	}
	tokenKey, exists = os.LookupEnv("TOKEN_KEY")
	if !exists {
		log.Fatal("could not find TOKEN_KEY in secrets.env")
	}

	// Connect to database
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			log.Fatal(err)
		}
	}()
	mainDB := client.Database("Main")
	usersCollection = mainDB.Collection("users")

	// Create gin api handlers
	router := gin.Default()
	router.POST("/register", registerHandler)
	router.POST("/login", loginHandler)
	router.POST("/verify", verifyHandler)
	router.POST("/changeEmail", authenticationMiddleware, changeEmailHandler)
	router.POST("/changePassword", authenticationMiddleware, changePasswordHandler)
	router.DELETE("/deleteAccount", authenticationMiddleware, deleteAccountHandler)
	router.POST("/ping", authenticationMiddleware, pingHandler)
	router.Run(":" + port)
}

type userClaims struct {
	Email string `json:"email"`
	IP    string `json:"username"`
	jwt.StandardClaims
}

func authenticationMiddleware(c *gin.Context) {
	defer handleError(c)
	if len(c.Request.Header["Authorization"]) < 1 {
		c.Abort()
		panic(authorizationRequired)
	}
	tokenHeader := strings.Split(c.Request.Header["Authorization"][0], " ")
	var tokenString string
	if len(tokenHeader) == 2 && tokenHeader[0] == "Bearer" {
		tokenString = tokenHeader[1]
	} else {
		c.Abort()
		panic(invalidTokenHeader)
	}

	fmt.Println(tokenString)
	token, err := jwt.ParseWithClaims(
		tokenString,
		&userClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(tokenKey), nil
		},
	)
	if err != nil {
		c.Abort()
		panic(invalidToken)
	}
	claims, ok := token.Claims.(*userClaims)
	if !ok {
		c.Abort()
		panic(invalidToken)
	}
	if claims.ExpiresAt < time.Now().UTC().Unix() {
		c.Abort()
		panic(expiredToken)
	}
	if claims.IP != c.ClientIP() {
		c.Abort()
		panic(invalidIP)
	}

	duplicateCount, err := usersCollection.CountDocuments(context.TODO(), bson.M{"email": claims.Email})
	if err != nil {
		c.Abort()
		panic(unknownError)
	}
	if duplicateCount == 0 {
		c.Abort()
		panic(invalidToken)
	}

	c.Set("email", claims.Email)
	c.Set("ip", claims.IP)
	c.Next()
}

func registerHandler(c *gin.Context) {
	defer handleError(c)
	email := c.PostForm("email")
	password := c.PostForm("password")
	if !isValidRegister(email, password) {
		panic(unacceptableValues)
	}
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		panic(unknownError)
	}
	hash := string(hashBytes)
	duplicateCount, err := usersCollection.CountDocuments(context.TODO(), bson.M{"email": email})
	if err != nil {
		panic(unknownError)
	}
	if duplicateCount > 0 {
		panic(emailInUse)
	}
	insertResult, err := usersCollection.InsertOne(context.TODO(), user{
		Email:    email,
		Password: hash,
		Verified: false,
		Auth:     rand.Int63(),
	})
	if err != nil {
		panic(unknownError)
	}
	c.String(201, fmt.Sprint(insertResult.InsertedID))
}

func loginHandler(c *gin.Context) {
	defer handleError(c)
	email := c.PostForm("email")
	password := c.PostForm("password")

	// Retrieve user
	var user bson.M
	err := usersCollection.FindOne(context.TODO(), bson.M{"email": email}).Decode(&user)
	if err != nil {
		panic(invalidLogin)
	}
	err = bcrypt.CompareHashAndPassword([]byte(fmt.Sprint(user["password"])), []byte(password))
	if err != nil {
		panic(invalidLogin)
	}

	// Issue token
	claims := userClaims{
		Email: email,
		IP:    c.ClientIP(),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(1)).Unix(),
			Issuer:    "localhost",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(tokenKey))
	c.String(200, signedToken)
}

func verifyHandler(c *gin.Context) {
	defer handleError(c)
	email := c.PostForm("email")
	auth := c.PostForm("auth")

	// Retrieve and check user document
	var user bson.M
	err := usersCollection.FindOne(context.TODO(), bson.M{"email": email}).Decode(&user)
	if err != nil {
		panic(unknownError)
	}
	if auth != fmt.Sprint(user["auth"]) {
		panic(invalidVerification)
	}
	if user["verified"].(bool) {
		panic(alreadyVerified)
	}

	// Update user document
	_, err = usersCollection.UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$set": bson.M{"verified": true}})
	if err != nil {
		panic(unknownError)
	}

	c.String(200, "verified")
}

func changeEmailHandler(c *gin.Context) {
	defer handleError(c)
	email, _ := c.Get("email")
	newEmail := c.PostForm("newEmail")

	if !isValidEmail(newEmail) {
		panic(unacceptableValues)
	}
	duplicateCount, err := usersCollection.CountDocuments(context.TODO(), bson.M{"email": newEmail})
	if err != nil {
		panic(unknownError)
	}
	if duplicateCount > 0 {
		panic(emailInUse)
	}
	// Update user document
	_, err = usersCollection.UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$set": bson.M{"verified": false, "email": newEmail}})
	if err != nil {
		panic(unknownError)
	}
	c.String(200, "email changed")
}

func changePasswordHandler(c *gin.Context) {
	defer handleError(c)
	email, _ := c.Get("email")
	newPassword := c.PostForm("newPassword")
	if !isValidRegister(email.(string), newPassword) {
		panic(unacceptableValues)
	}
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		panic(unknownError)
	}
	hash := string(hashBytes)

	// Update user document
	_, err = usersCollection.UpdateOne(context.TODO(), bson.M{"email": email}, bson.M{"$set": bson.M{"password": hash}})
	if err != nil {
		panic(unknownError)
	}
	c.String(200, "password changed")
}

func deleteAccountHandler(c *gin.Context) {
	defer handleError(c)
	email, _ := c.Get("email")
	_, err := usersCollection.DeleteOne(context.TODO(), bson.M{"email": email})
	if err != nil {
		panic(unknownError)
	}
	c.String(200, "deleted")
}

// For development
func pingHandler(c *gin.Context) {
	email, _ := c.Get("email")
	ip, _ := c.Get("ip")
	c.String(200, fmt.Sprintf("%s \n %s", email, ip))
}
