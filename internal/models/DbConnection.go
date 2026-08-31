package models

// DbConnection is a struct that contains the database configuration for connecting
type DbConnection struct {
	HostUrl         string
	RedisPrefix     string
	DatabaseName    string
	PostgresSslMode string
	Username        string
	Password        string
	RedisUseSsl     bool
	Type            int
}
