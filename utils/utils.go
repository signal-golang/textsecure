package utils

import "os"

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
