package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-contrib/timeout"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4" // Update import to v4 not v5
	"github.com/rs/xid"
)

//All your dependencies should share the same context (important)

// User struct represents a user in the database
type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}
type Message struct {
	Output string `json:"output"`
}
type File struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// Token struct represents the JWT token
type Token struct {
	Token string `json:"token"`
}

// Users slice stores the registered users
var Users []User

// JWT secret key
var jwtKey = []byte("your-secret-key")

// Claims struct represents the JWT claims
type Claims struct {
	Username  string `json:"username"`
	UserID    string `json:"user_id"`
	RequestID string `json:"request_id"`
	jwt.RegisteredClaims
}

// timeout response function
func timeOutResponse(c *gin.Context) {
	c.String(http.StatusRequestTimeout, "handler took too long to respond")
}

// timeoutMiddleware Function
func timeoutMiddleware() gin.HandlerFunc {
	return timeout.New(
		timeout.WithTimeout(500*time.Millisecond),
		//this passes it on to the handlers
		timeout.WithHandler(func(c *gin.Context) {
			c.Next()
		}),
		timeout.WithResponse(timeOutResponse),
	)
}
func main() {
	//create a directory uploads
	err := os.MkdirAll("uploads", os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
	router := gin.Default()

	//all routes will use the timeout middleware
	router.Use(timeoutMiddleware())
	// Unprotected routes
	router.POST("/register", registerHandler)
	router.POST("/login", loginHandler)
	router.POST("/refresh", refreshHandler)

	// Protected routes
	authRouter := router.Group("/auth")

	authRouter.Use(authMiddleware)
	{

		authRouter.GET("/users", usersListHandler)
		authRouter.POST("/upload", uploadHandler)
		authRouter.GET("/open/:filename", openImageHandler)
	}

	//this creates the server
	router.Run(":8000")
}

// Middleware to authenticate the JWT token
func authMiddleware(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		unauthorizedError(c)
		return
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			unauthorizedError(c)
			return
		}
		badRequestError(c)
		return
	}
	if !token.Valid {
		unauthorizedError(c)
		return
	}
	claims := token.Claims.(*Claims)
	c.Set("claimsUserName", claims.Username)
	c.Set("claimsUserId", claims.UserID)
	c.Set("claimsRequestId", claims.RequestID)
	c.Next()
}

// Register handler creates a new user
func registerHandler(c *gin.Context) {
	if err := createUser(c); err != nil {
		internalServerError(c)
		return
	}

	messageInfo := Message{
		Output: "user successfuly created",
	}

	c.JSON(http.StatusCreated, messageInfo)
}

// Login handler validates the user credentials and returns a JWT token
func loginHandler(c *gin.Context) {
	//creates an instance of the User struct
	credentials := User{}
	//login only binds that user
	if err := c.ShouldBindJSON(&credentials); err != nil {
		badRequestError(c)
		return
	}
	c.Set("credentialsId", credentials.ID)
	c.Set("credentialsUserName", credentials.Username)
	c.Set("credentialsPassword", credentials.Password)

	if !validateCredentials(c) {
		unauthorizedError(c)
		return
	}

	// once a user is logged in a jwt token is generated
	RequestID := generateRequestID(c)
	c.Set("requestId", RequestID)
	generateTokenResponse(c)
	c.JSON(http.StatusCreated, gin.H{"status": "user logged in successfully"})

}

func refreshHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		unauthorizedError(c)
		return
	}

	claims := token.Claims.(*Claims)
	c.Set("claims", claims)

	// Fix this later
	//no time windowfor refreshing token
	// remainingValidity := time.Until(claims.ExpiresAt.Time)
	// if remainingValidity < 30*time.Minute || remainingValidity > 5*time.Hour {
	// 	badRequestError(c)
	// 	return
	//
	RequestID := generateRequestID(c)
	c.Set("requestId", RequestID)

	generateTokenResponse(c)
}

// Users List handler returns the list of users in the users struct/database
func usersListHandler(c *gin.Context) {
	users := copyUsersList(c)
	c.JSON(http.StatusOK, users)
}

// If the request includes binary data (set the default to 32 MB maximum)
func uploadHandler(c *gin.Context) {
	//set the default to 32 MB maximum
	file, err := c.FormFile("file")
	if err != nil {
		badRequestError(c)
		return
	}
	c.Set("filename", file.Filename)
	filename := generateFilename(c)
	if err := c.SaveUploadedFile(file, "uploads/"+filename); err != nil {
		internalServerError(c)
		return
	}
	fileInfo := File{
		Name: filename,
		Path: "uploads/" + filename,
		Size: file.Size,
	}
	c.JSON(http.StatusOK, fileInfo)
}

func openImageHandler(c *gin.Context) {
	filename := c.Param("filename")
	filePath := filepath.Join("./uploads/" + filename)
	// c.Set("filePath", filePath)
	// Check if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		internalServerError(c)
		return

	}
	//if the file exists
	//open the image file
	file, err := os.Open(filePath)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Image not found"})
		return
	}
	defer file.Close()

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get file"})
		return
	}
}

////HELPER FUNCTIONS

// Helper function to create a new user
func createUser(c *gin.Context) error {
	user := User{} //create a new insance of a user
	if err := c.ShouldBindJSON(&user); err != nil {
		return err
	}
	//createUser appends the user to the list of Users
	Users = append(Users, user)
	return nil
}

// helper function to validate user credentials
func validateCredentials(c *gin.Context) bool {
	//Validate Credentials works by going through the registered User struct and checking if the newly created credentials instance(when logging in) of the User struct is the same as the user in the Users struct

	credentialsId := c.GetString("credentialsId")
	credentialsUserName := c.GetString("credentialsUserName")
	credentialsPassword := c.GetString("credentialsPassword")
	for _, user := range Users {

		if user.ID == credentialsId && user.Username == credentialsUserName && user.Password == credentialsPassword {
			return true
		}
	}
	return false
}

// Helper function to generate a JWT token
func generateTokenResponse(c *gin.Context) {
	expirationTime := time.Now().Add(30 * time.Minute)

	claimsUserName := c.GetString("claimsUserName")
	claimsUserId := c.GetString("claimsUserId")
	claimsRequestId := c.GetString("claimsRequestId")

	claims := &Claims{
		Username:  claimsUserName,
		UserID:    claimsUserId,
		RequestID: claimsRequestId,

		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: expirationTime},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // this creates a new Token
	tokenString, err := token.SignedString(jwtKey)             // this creates a signed jwt
	if err != nil {
		internalServerError(c)
		return
	}

	response := Token{Token: tokenString}
	c.JSON(http.StatusOK, response)
}

// Helper function to create a copy of the users list
func copyUsersList(c *gin.Context) []User {
	users := make([]User, len(Users))
	copy(users, Users)
	return users
}
func generateRequestID(c *gin.Context) string {
	guid := xid.New().String()
	return guid
}

// Helper function to generate a unique filename
func generateFilename(c *gin.Context) string {
	originalFilename, _ := c.Get("filename")
	timestamp := time.Now().UnixNano()
	return strconv.FormatInt(timestamp, 10) + "_" + originalFilename.(string)
}

// Helper function to handle unauthorized error --401
func unauthorizedError(c *gin.Context) {
	c.AbortWithStatus(http.StatusUnauthorized)
}

// Optional
// Helper function to handle bad request error-- 400
func badRequestError(c *gin.Context) {
	c.AbortWithStatus(http.StatusBadRequest)

}

// Helper function to handle internal server error-500
func internalServerError(c *gin.Context) {
	c.AbortWithStatus(http.StatusInternalServerError)
	return
}

// UNABLE TO SAVE ERROR--500
func unableToSave(c *gin.Context) {
	c.AbortWithStatus(http.StatusInternalServerError)
}

// Helper function to handle not found error--404
func notFoundError(c *gin.Context) {
	c.AbortWithStatus(http.StatusNotFound)
}

// // helper function to handle a request timeOut-- 408
// func requestTimeOut(c *gin.Context) {
// 	c.AbortWithStatus(http.StatusRequestTimeout)
// }
