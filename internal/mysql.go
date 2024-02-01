package internal

import (
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

var DB *sqlx.DB

func init() {
	db, err := sqlx.Connect("mysql", "root:root@(localhost:3306)/aki")
	if err != nil {
		panic(err)
	}
	DB = db
}
