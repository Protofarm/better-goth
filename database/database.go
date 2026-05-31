package database

import (
	"context"
	"database/sql"
	"errors"
	"log"

	"github.com/Protofarm/better-goth/oauth-server/models"
	"github.com/Protofarm/better-goth/pb"
	"github.com/Protofarm/better-goth/providers"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/schema"

	_ "github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun/dialect/mysqldialect"

	"github.com/uptrace/bun/dialect/pgdialect"
	_ "github.com/uptrace/bun/driver/pgdriver"

	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

type Instance struct {
	DB *bun.DB
}

func InitDB(connType, connStr string) (*Instance, error) {
	ctx := context.Background()

	var d schema.Dialect
	switch connType {
	case "mysql":
		d = mysqldialect.New()
	case "postgres":
		d = pgdialect.New()
	case "sqlite":
		connType = sqliteshim.ShimName
		d = sqlitedialect.New()
	case "memory":
		connType = sqliteshim.ShimName
		d = sqlitedialect.New()
		connStr = ":memory:"
	default:
		return nil, errors.New("Invalid connection type.")
	}

	sqldb, err := sql.Open(connType, connStr)
	if err != nil {
		return nil, err
	}

	db := bun.NewDB(sqldb, d)
	dbin := &Instance{DB: db}

	_, err = db.NewCreateTable().Model((*models.User)(nil)).IfNotExists().Exec(ctx)
	if err != nil {
		log.Fatal(err)
		return dbin, errors.New("Unable to create 'users' Table.")
	}

	_, err = db.NewCreateTable().Model((*models.UserIdentity)(nil)).IfNotExists().Exec(ctx)
	if err != nil {
		log.Fatal(err)
		return dbin, errors.New("Unable to create 'user_identities' Table.")
	}

	_, err = db.NewCreateTable().Model((*models.DBToken)(nil)).IfNotExists().Exec(ctx)
	if err != nil {
		log.Fatal(err)
		return dbin, errors.New("Unable to create 'tokens' Table.")
	}

	return dbin, nil
}

func (db *Instance) CreateUser(user *models.User) error {
	_, err := db.DB.NewInsert().Model(user).Exec(context.Background())
	return err
}

func (db *Instance) GetUserByID(id string) (*models.User, error) {
	user := new(models.User)

	err := db.DB.NewSelect().Model(user).Where("id = ?", id).Scan(context.Background())
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (db *Instance) GetUserByEmail(email string) (*models.User, error) {
	user := new(models.User)

	err := db.DB.NewSelect().Model(user).Where("email = ?", email).Scan(context.Background())
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (db *Instance) GetUserByName(name string) (*models.User, error) {
	user := new(models.User)

	err := db.DB.NewSelect().Model(user).Where("name = ?", name).Scan(context.Background())
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (db *Instance) CreateUserIdentity(identity *models.UserIdentity) error {
	_, err := db.DB.NewInsert().Model(identity).Exec(context.Background())
	return err
}

func (db *Instance) GetCorrespondingUser(identity_id string) (*models.User, error) {
	user := new(models.User)
	err := db.DB.NewSelect().Model(user).Where("id = ", identity_id).Relation("user_identities").Scan(context.Background())
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (db *Instance) CheckUserIdentityExists(userid string) bool {
	count, err := db.DB.NewSelect().
		Model((*models.UserIdentity)(nil)).
		Where("user_id = ?", userid).
		Where("provider = ?", providers.OAuthServerProviderName).
		Count(context.Background())
	if err != nil {
		log.Printf("Error checking user identity existence: %v", err)
		return false
	}
	return count > 0
}

func (db *Instance) GetOrCreateUser(pbuser *pb.User, provider string) *pb.User {
	user, err := db.GetUserByEmail(pbuser.Email)
	if err != nil {
		user = &models.User{
			ID:             uuid.New().String(),
			Email:          pbuser.GetEmail(),
			Name:           pbuser.GetName(),
			GivenName:      pbuser.GetGivenName(),
			Picture:        pbuser.GetPicture(),
			EmailConfirmed: pbuser.GetEmailVerified(),
		}
		err = db.CreateUser(user)
		if err != nil {
			return pbuser
		}
	}

	ui := &models.UserIdentity{
		ID:       uuid.New().String(),
		UserID:   user.ID,
		Sub:      pbuser.GetSub(),
		Provider: provider,
	}
	db.CreateUserIdentity(ui)

	return &pb.User{
		Picture:       user.Picture,
		Name:          user.Name,
		Email:         user.Email,
		GivenName:     user.GivenName,
		EmailVerified: user.EmailConfirmed,
		Iat:           pbuser.GetIat(),
		Exp:           pbuser.GetExp(),
		Iss:           pbuser.GetIss(),
		Sub:           user.ID,
		Azp:           pbuser.GetAzp(),
		Aud:           pbuser.GetAud(),
		AtHash:        pbuser.GetAtHash(),
	}
}
