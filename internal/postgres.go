package internal

import (
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
)

// DB is the global database handle (PostgreSQL)
var DB *sqlx.DB

func init() {
	// AuthServerConfig.DB expected format example:
	// postgres://user:pass@host:5432/auth?sslmode=disable
	db, err := sqlx.Connect("pgx", AuthServerConfig.DB)
	if err != nil {
		panic(err)
	}
	DB = db
}
