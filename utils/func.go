package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

/**
 * Function: WriteToFile
 * @Description: write io.WriterTo item to file
 * @param item: io.WriterTo item
 * @param path: file path
 */
func WriteToFile(item io.WriterTo, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", path, err)
	}
	_, err = item.WriteTo(file)
	if err != nil {
		return err
	}
	return file.Close()
}

/*
 * Function: FixupNewlines
 * @Description: convert LF newlines to CRLF newlines
 * @param s: input string
 * @return: string with CRLF newlines
 */
func FixupNewlines(s string) string {
	return strings.Replace(s, "\n", "\r\n", -1)
}
