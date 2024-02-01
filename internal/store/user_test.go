package store

import (
	"auth-server/internal"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"testing"
)

func TestDB(t *testing.T) {
	var row []string
	_ = internal.DB.Select(&row, "show tables ")
	log.Println(row)
}
