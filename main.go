//In the name of Allah

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func GenerateRefreshToken() string {
	bytes := make([]byte, 64)
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err) // Handle error appropriately in your application
	}
	return base64.StdEncoding.EncodeToString(bytes)
} //func

func RefreshTokenHelper() {
	refreshToken := GenerateRefreshToken()
	fmt.Println("Refresh Token:", refreshToken)
} //func

func RefreshTokenDecoderBase64(encodedStr string) (string, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return "", err
	}
	return string(decodedBytes), nil
} //func

func RefreshTokenDecodeHelper(encodedToken string) {
	decodedToken, err := RefreshTokenDecoderBase64(encodedToken)
	if err != nil {
		fmt.Println("Error decoding:", err)
		return
	}
	fmt.Println("Decoded Refresh Token:", decodedToken)
} //func

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Payload struct {
	FirstName string `json:"FirstName"`
	LastName  string `json:"LastName"`
	UserName  string `json:"UserName"`
	UserType  string `json:"UserType"`
	Id        int    `json:"id"`
	Jti       string `json:"jti"`
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
}

func base64UrlEncode(data []byte) string {
	str := base64.StdEncoding.EncodeToString(data)
	str = strings.Replace(str, "+", "-", -1)
	str = strings.Replace(str, "/", "_", -1)
	str = strings.Replace(str, "=", "", -1)
	return str
}

func CreateAccessToken(user map[string]string, secret string, exp time.Duration) (string, error) {
	header := Header{
		Alg: "HS256",
		Typ: "JWT",
	}

	id, err := strconv.Atoi(user["id"])
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	payload := Payload{
		FirstName: user["FirstName"],
		LastName:  user["LastName"],
		UserName:  user["UserName"],
		UserType:  user["UserType"],
		Id:        id,
		Jti:       user["jti"],
		Iat:       now,
		Exp:       now + int64(exp.Seconds()),
	}

	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(payload)

	headerAndPayload := base64UrlEncode(headerBytes) + "." + base64UrlEncode(payloadBytes)

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(headerAndPayload))

	signature := base64UrlEncode(h.Sum(nil))

	return headerAndPayload + "." + signature, nil
} //func

func base64UrlDecode(data string) ([]byte, error) {
	// Add back missing padding
	for len(data)%4 != 0 {
		data += "="
	}

	return base64.URLEncoding.DecodeString(data)
}

func decodeToken(token string) (Header, Payload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Header{}, Payload{}, fmt.Errorf("invalid token")
	}

	headerBytes, err := base64UrlDecode(parts[0])
	if err != nil {
		return Header{}, Payload{}, err
	}

	payloadBytes, err := base64UrlDecode(parts[1])
	if err != nil {
		return Header{}, Payload{}, err
	}

	var header Header
	err = json.Unmarshal(headerBytes, &header)
	if err != nil {
		return Header{}, Payload{}, err
	}

	var payload Payload
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return Header{}, Payload{}, err
	}

	return header, payload, nil
} //func

func GeneratorHelper() {
	user := map[string]string{
		"FirstName": "John",
		"LastName":  "Doe",
		"UserName":  "johndoe",
		"UserType":  "Customer",
		"id":        "123",
		"jti":       "unique_identifier",
	}

	secret := "your_secret_key_here"

	token, err := CreateAccessToken(user, secret, 15*time.Minute)
	if err != nil {
		fmt.Println("Error creating token:", err)
		return
	}

	fmt.Println("Token:", token)
} //func

func DecodeHelper() {
	accessToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJGaXJzdE5hbWUiOiJzeXN0ZW0gYWRtaW4iLCJMYXN0TmFtZSI6IiIsIlVzZXJOYW1lIjoic3lzdXNlckBnbWFpbC5jb20iLCJVc2VyVHlwZSI6IkNNUyIsImlkIjo2ODgsImp0aSI6ImMxM2VkYWY2LTg4ODMtNDYyOS05ZTc2LTYwMDY1OGVlNzU5NCIsImV4cCI6MTcyODA2NTMzMCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo1MDAxIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo0MjAwIn0.gJjLjY_-XQy6OC3EocwH0m-trDf1XugHKvCZJGg4ADY"
	refreshToken := "your_refresh_token_here"

	header, payload, err := decodeToken(accessToken)
	if err != nil {
		fmt.Println("Error decoding access token:", err)
	} else {
		fmt.Println("Access Token Header:", header)
		fmt.Println("Access Token Payload:", payload)
	}

	header, payload, err = decodeToken(refreshToken)
	if err != nil {
		fmt.Println("Error decoding refresh token:", err)
	} else {
		fmt.Println("Refresh Token Header:", header)
		fmt.Println("Refresh Token Payload:", payload)
	}
} //func

func verifySignature(token string, secret string) (bool, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid token")
	}

	headerAndPayload := parts[0] + "." + parts[1]
	signature, err := base64UrlDecode(parts[2])
	if err != nil {
		return false, err
	}

	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(headerAndPayload))

	computedSignature := h.Sum(nil)

	return hmac.Equal(signature, computedSignature), nil
} //func

func main() {
	// GeneratorHelper()
	// DecodeHelper()
	// token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJGaXJzdE5hbWUiOiJzeXN0ZW0gYWRtaW4iLCJMYXN0TmFtZSI6IiIsIlVzZXJOYW1lIjoic3lzdXNlckBnbWFpbC5jb20iLCJVc2VyVHlwZSI6IkNNUyIsImlkIjo2ODgsImp0aSI6ImMxM2VkYWY2LTg4ODMtNDYyOS05ZTc2LTYwMDY1OGVlNzU5NCIsImV4cCI6MTcyODA2NTMzMCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo1MDAxIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo0MjAwIn0.gJjLjY_-XQy6OC3EocwH0m-trDf1XugHKvCZJGg4ADY"
	// secret := "f64971ec641a43a71c7912f957eefaae112ddf1f"
	// isValid, _ := verifySignature(token, secret)
	// fmt.Printf("%v", isValid)

	//RefreshTokenHelper()
	RefreshTokenDecodeHelper("bm/sxTTyNjYXKVYcICjxVy5KSJOXx2VtsBXH3BXZAVxYV0amUCp3xRXHtIT5fue1aagZo8TOl5dEeAYnEMqfDw==")
}
