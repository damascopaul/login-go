package main

import (
	"net/http"
	"os"
	"time"

	"github.com/damascopaul/login-go/middlewares"
	"github.com/damascopaul/login-go/types"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

var log = logrus.New()

func main() {
	log.SetFormatter(&logrus.JSONFormatter{})
	r := gin.Default()
	r.Use(middlewares.InjectRequestIDMiddleware)
	r.POST("/login", processLogin)
	r.Run() // listen and serve on 0.0.0.0:8080
}

func buildToken(s string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": "u-777",
		"nbf":  time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})
	ts, err := t.SignedString([]byte(s))
	if err != nil {
		return "", err
	}
	return ts, nil
}

func formatValidationErrors(errs validator.ValidationErrors) []types.FieldError {
	errMsg := map[string]string{
		"email":    "not a valid email",
		"required": "field is required",
	}
	fe := make([]types.FieldError, len(errs))
	for i, validationError := range errs {
		fe[i] = types.FieldError{Error: errMsg[validationError.Tag()], Name: validationError.Field()}
	}
	return fe
}

func processLogin(c *gin.Context) {
	reqID, _ := c.Get("RequestID")
	log.WithFields(logrus.Fields{"request": reqID}).Info("Request received")

	c.Header("Content-Type", "application/json")

	var req types.RequestBody
	if err := c.BindJSON(&req); err != nil {
		log.WithFields(logrus.Fields{
			"error":   err.Error(),
			"request": reqID,
		}).Warn("Failed to parse request body")
		c.AbortWithStatusJSON(
			http.StatusBadRequest, types.ResponseError{Message: "This only supports JSON"})
		return
	}
	log.WithFields(logrus.Fields{"request": reqID}).Info("Parsed the request body")

	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		log.WithFields(logrus.Fields{
			"error":   err.Error(),
			"request": reqID,
		}).Warn("Validation on request body failed")
		c.AbortWithStatusJSON(http.StatusBadRequest, types.ResponseError{
			Message:     "The request body has errors",
			FieldErrors: formatValidationErrors(err.(validator.ValidationErrors)),
		})
		return
	}
	log.WithFields(logrus.Fields{"request": reqID}).Info("Validated the request body")

	secret := os.Getenv("TOKEN_SECRET")
	if secret == "" {
		log.WithFields(logrus.Fields{
			"error":   "The token secret is not configured",
			"request": reqID,
		}).Fatal("App configuration error")
		c.AbortWithStatusJSON(
			http.StatusInternalServerError, types.ResponseError{Message: "Server error encountered"})
		return
	}

	t, err := buildToken(secret)
	if err != nil {
		log.WithFields(logrus.Fields{
			"error":   err.Error(),
			"request": reqID,
		}).Warn("Failed to build JWT")
		c.AbortWithStatusJSON(
			http.StatusInternalServerError, types.ResponseError{Message: "Server error encountered"})
		return
	}
	log.WithFields(logrus.Fields{"request": reqID}).Info("Token built")

	c.JSON(http.StatusOK, types.ResponseBody{Token: t})
	log.WithFields(logrus.Fields{"request": reqID}).Info("Request processed")
}
