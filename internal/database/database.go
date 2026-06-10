package database

import (
	"context"
	"database/sql"
	"errors"
	"log"

	"github.com/Protofarm/better-goth/internal/oauth-server/models"
	"github.com/Protofarm/better-goth/internal/pb"
	"github.com/Protofarm/better-goth/internal/providers"
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

type WriteJob func(bun.Tx) error

type Instance struct {
	DB      *bun.DB
	writeCh chan WriteJob
	enqueue func(WriteJob) error
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
	dbin := &Instance{
		DB:      db,
		writeCh: make(chan WriteJob),
	}
	if connType == sqliteshim.ShimName {
		dbin.DB.SetMaxOpenConns(1)
		go dbin.runWriter()
		dbin.enqueue = dbin.EnqueueWrite
	} else {
		dbin.enqueue = dbin.EnqueueDirectWrite
	}

	tables := []struct {
		model any
		name  string
	}{
		{(*models.User)(nil), "users"},
		{(*models.UserIdentity)(nil), "user_identities"},
		{(*models.DBToken)(nil), "tokens"},
		{(*models.Client)(nil), "clients_info"},
	}
	for _, t := range tables {
		if _, err := db.NewCreateTable().Model(t.model).IfNotExists().Exec(ctx); err != nil {
			log.Printf("unable to create '%s' table: %v", t.name, err)
			return nil, err
		}
	}

	return dbin, nil
}

func (db *Instance) Close() error {
	close(db.writeCh)
	return db.DB.Close()
}

func (db *Instance) runWriter() {
	for job := range db.writeCh {
		err := db.DB.RunInTx(context.Background(), nil, func(ctx context.Context, tx bun.Tx) error {
			return job(tx)
		})
		if err != nil {
			log.Printf("Write job error: %v", err)
		}
	}
}

func (db *Instance) EnqueueDirectWrite(job WriteJob) error {
	return db.DB.RunInTx(context.Background(), nil, func(ctx context.Context, tx bun.Tx) error {
		return job(tx)
	})
}

func (db *Instance) EnqueueWrite(job WriteJob) error {
	done := make(chan error, 1)
	db.writeCh <- func(tx bun.Tx) error {
		err := job(tx)
		done <- err
		return err
	}
	return <-done
}

func (db *Instance) CreateUser(user *models.User) error {
	return db.enqueue(func(tx bun.Tx) error {
		_, err := tx.NewInsert().Model(user).Exec(context.Background())
		return err
	})
}

func (db *Instance) GetUserByID(id string) (*models.User, error) {
	user := new(models.User)

	err := db.enqueue(func(tx bun.Tx) error {
		return tx.NewSelect().Model(user).Where("id = ?", id).Scan(context.Background())
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (db *Instance) GetUserByEmail(email string) (*models.User, error) {
	user := new(models.User)

	err := db.enqueue(func(tx bun.Tx) error {
		return tx.NewSelect().Model(user).Where("email = ?", email).Scan(context.Background())
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (db *Instance) GetUserByName(name string) (*models.User, error) {
	user := new(models.User)

	err := db.enqueue(func(tx bun.Tx) error {
		return tx.NewSelect().Model(user).Where("name = ?", name).Scan(context.Background())
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (db *Instance) CreateUserIdentity(identity *models.UserIdentity) error {
	return db.enqueue(func(tx bun.Tx) error {
		_, err := tx.NewInsert().Model(identity).Exec(context.Background())
		return err
	})
}

func (db *Instance) ConfirmEmailByUserID(userID string) error {
	return db.enqueue(func(tx bun.Tx) error {
		_, err := tx.NewUpdate().
			Model((*models.User)(nil)).
			Set("email_confirmed = ?", true).
			Where("id = ?", userID).
			Exec(context.Background())
		return err
	})
}

func (db *Instance) GetCorrespondingUser(identity_id string) (*models.User, error) {
	user := new(models.User)
	err := db.enqueue(func(tx bun.Tx) error {
		return tx.NewSelect().Model(user).Where("id = ?", identity_id).Relation("user_identities").Scan(context.Background())
	})
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (db *Instance) CheckUserIdentityExists(userid string) bool {
	var count int
	err := db.enqueue(func(tx bun.Tx) error {
		var err error
		count, err = tx.NewSelect().
			Model((*models.UserIdentity)(nil)).
			Where("user_id = ?", userid).
			Where("provider = ?", providers.OAuthServerProviderName).
			Count(context.Background())
		return err
	})
	if err != nil {
		log.Printf("Error checking user identity existence: %v", err)
		return false
	}
	return count > 0
}

func (db *Instance) GetOrCreateUser(pbuser *pb.User, provider string) (*pb.User, error) {
	user := new(models.User)

	err := db.enqueue(func(tx bun.Tx) error {
		ctx := context.Background()

		err := tx.NewSelect().Model(user).Where("email = ?", pbuser.GetEmail()).Scan(ctx)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		*user = models.User{
			ID:             uuid.New().String(),
			Email:          pbuser.GetEmail(),
			Name:           pbuser.GetName(),
			GivenName:      pbuser.GetGivenName(),
			Picture:        pbuser.GetPicture(),
			EmailConfirmed: pbuser.GetEmailVerified(),
		}
		if _, err := tx.NewInsert().Model(user).Exec(ctx); err != nil {
			return err
		}

		ui := &models.UserIdentity{
			ID:       uuid.New().String(),
			UserID:   user.ID,
			Sub:      pbuser.GetSub(),
			Provider: provider,
		}
		_, err = tx.NewInsert().Model(ui).Exec(ctx)
		return err
	})
	if err != nil {
		return nil, err
	}

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
	}, nil
}

func (db *Instance) GetClientByID(id string) (*models.Client, error) {
	client := new(models.Client)

	err := db.enqueue(func(tx bun.Tx) error {
		return tx.NewSelect().Model(client).Where("id = ?", id).Scan(context.Background())
	})
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (db *Instance) GetClientByUserID(userID string) (*models.Client, error) {
	client := new(models.Client)

	err := db.enqueue(func(tx bun.Tx) error {
		return tx.NewSelect().Model(client).Where("user_id = ?", userID).Scan(context.Background())
	})
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (db *Instance) CreateClient(ci *models.Client) error {
	return db.enqueue(func(tx bun.Tx) error {
		_, err := tx.NewInsert().Model(ci).Exec(context.Background())
		return err
	})
}

func (db *Instance) UpdateClient(ci *models.Client) error {
	return db.enqueue(func(tx bun.Tx) error {
		_, err := tx.NewUpdate().Model(ci).Where("id = ?", ci.ID).Exec(context.Background())
		return err
	})
}

func (db *Instance) DeleteClient(id string) error {
	return db.enqueue(func(tx bun.Tx) error {
		_, err := tx.NewDelete().Model((*models.Client)(nil)).Where("id = ?", id).Exec(context.Background())
		return err
	})
}
