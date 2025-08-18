package entities

type UserScope struct {
	ID   int64  `gorm:"primaryKey"`
	Name string `gorm:"type:varchar(50);unique;not null"`
}
