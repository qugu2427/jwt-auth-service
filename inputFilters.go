package main

import "strings"

func isValidEmail(email string) bool {
	splitEmail := strings.Split(email, "@")
	return len(splitEmail) == 2 &&
		len(splitEmail[0]) != 0 &&
		len(splitEmail[1]) >= 3 &&
		len(strings.Split(splitEmail[1], ".")) == 2
}

func isValidRegister(email string, password string) bool {
	return isValidEmail(email) && len(email) < 50 && len(password) > 10 && len(password) < 50
}
