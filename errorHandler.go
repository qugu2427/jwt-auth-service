package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

type errorResponse struct {
	status int
	name   string
}

var unknownError = errorResponse{500, "UnknownError"}
var unacceptableValues = errorResponse{400, "UnacceptableValues"}
var invalidLogin = errorResponse{401, "InvalidLogin"}
var invalidVerification = errorResponse{400, "InvalidVerification"}
var invalidToken = errorResponse{401, "InvalidToken"}
var invalidTokenHeader = errorResponse{401, "InvalidTokenHeader"}
var expiredToken = errorResponse{401, "ExpiredToken"}
var invalidIP = errorResponse{401, "InvalidIP"}
var alreadyVerified = errorResponse{400, "AlreadyVerified"}
var authorizationRequired = errorResponse{401, "AuthorizationRequired"}
var emailInUse = errorResponse{400, "EmailInUse"}

func handleError(c *gin.Context) {
	if r := recover(); r != nil {
		fmt.Println(r) // For developement
		c.String(r.(errorResponse).status, r.(errorResponse).name)
	}
}
