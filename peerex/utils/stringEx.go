package utils

import (
	"strings"
)

func IsNullOrEmpty(str string) bool {
	str = strings.Trim(str, " ")
	if str == "" {
		return true
	}
	return false
}
