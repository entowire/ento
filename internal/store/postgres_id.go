package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// idSchema holds the identity provider's tables (id.go).
const idSchema = `
CREATE TABLE IF NOT EXISTS ento_id_people (
	id           text PRIMARY KEY,
	email        text NOT NULL UNIQUE,
	given_name   text NOT NULL DEFAULT '',
	family_name  text NOT NULL DEFAULT '',
	groups       text[] NOT NULL DEFAULT '{}',
	disabled     boolean NOT NULL DEFAULT false,
	created_at   timestamptz NOT NULL,
	last_sign_in timestamptz
);
ALTER TABLE ento_id_people ADD COLUMN IF NOT EXISTS password text NOT NULL DEFAULT '';
ALTER TABLE ento_id_people ADD COLUMN IF NOT EXISTS totp bytea;
ALTER TABLE ento_id_people ADD COLUMN IF NOT EXISTS totp_step bigint NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS ento_id_passkeys (
	credential_id bytea PRIMARY KEY,
	person_id     text NOT NULL REFERENCES ento_id_people (id) ON DELETE CASCADE,
	name          text NOT NULL,
	credential    bytea NOT NULL,
	created_at    timestamptz NOT NULL,
	last_used     timestamptz,
	UNIQUE (person_id, name)
);
CREATE TABLE IF NOT EXISTS ento_id_groups (
	name   text PRIMARY KEY,
	kind   text NOT NULL DEFAULT '',
	signin text[] NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS ento_id_state (
	key        text PRIMARY KEY,
	kind       text NOT NULL,
	person     text NOT NULL DEFAULT '',
	data       bytea NOT NULL,
	expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS ento_id_state_person ON ento_id_state (person, kind);
CREATE INDEX IF NOT EXISTS ento_id_state_expires ON ento_id_state (expires_at);
`

const idPersonColumns = `id, email, given_name, family_name, groups, disabled, created_at, last_sign_in, password, totp, totp_step`

func scanIDPerson(row pgx.Row) (IDPerson, error) {
	var p IDPerson
	var last *time.Time
	err := row.Scan(&p.ID, &p.Email, &p.GivenName, &p.FamilyName, &p.Groups, &p.Disabled, &p.CreatedAt, &last, &p.Password, &p.TOTP, &p.TOTPStep)
	if errors.Is(err, pgx.ErrNoRows) {
		return IDPerson{}, ErrNotFound
	}
	if last != nil {
		p.LastSignIn = *last
	}
	if p.Groups == nil {
		p.Groups = []string{}
	}
	return p, err
}

func (p *Postgres) IDPeople(ctx context.Context) ([]IDPerson, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+idPersonColumns+` FROM ento_id_people ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IDPerson
	for rows.Next() {
		x, err := scanIDPerson(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func (p *Postgres) IDPerson(ctx context.Context, id string) (IDPerson, error) {
	return scanIDPerson(p.pool.QueryRow(ctx, `SELECT `+idPersonColumns+` FROM ento_id_people WHERE id = $1`, id))
}

func (p *Postgres) IDPersonByEmail(ctx context.Context, email string) (IDPerson, error) {
	return scanIDPerson(p.pool.QueryRow(ctx, `SELECT `+idPersonColumns+` FROM ento_id_people WHERE email = $1`, email))
}

func (p *Postgres) CreateIDPerson(ctx context.Context, x IDPerson) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO ento_id_people (`+idPersonColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		x.ID, x.Email, x.GivenName, x.FamilyName, nonNil(x.Groups), x.Disabled, x.CreatedAt, nullTime(x.LastSignIn), x.Password, x.TOTP, x.TOTPStep)
	if isUniqueViolation(err) {
		return ErrExists
	}
	return err
}

func (p *Postgres) UpdateIDPerson(ctx context.Context, id string, fn func(IDPerson) (IDPerson, error)) (IDPerson, error) {
	var out IDPerson
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		cur, err := scanIDPerson(tx.QueryRow(ctx, `SELECT `+idPersonColumns+` FROM ento_id_people WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		n, err := fn(cur)
		if err != nil {
			return err
		}
		n.ID = id
		_, err = tx.Exec(ctx, `UPDATE ento_id_people SET email = $2, given_name = $3, family_name = $4, groups = $5,
			disabled = $6, last_sign_in = $7, password = $8, totp = $9, totp_step = $10 WHERE id = $1`,
			id, n.Email, n.GivenName, n.FamilyName, nonNil(n.Groups), n.Disabled, nullTime(n.LastSignIn), n.Password, n.TOTP, n.TOTPStep)
		if isUniqueViolation(err) {
			return ErrExists
		}
		out = n
		return err
	})
	return out, err
}

func (p *Postgres) DeleteIDPerson(ctx context.Context, id string) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM ento_id_people WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `DELETE FROM ento_id_state WHERE person = $1`, id)
		return err
	})
}

const idPasskeyColumns = `credential_id, person_id, name, credential, created_at, last_used`

func scanIDPasskey(row pgx.Row) (IDPasskey, error) {
	var k IDPasskey
	var last *time.Time
	err := row.Scan(&k.CredentialID, &k.PersonID, &k.Name, &k.Credential, &k.CreatedAt, &last)
	if errors.Is(err, pgx.ErrNoRows) {
		return IDPasskey{}, ErrNotFound
	}
	if last != nil {
		k.LastUsed = *last
	}
	return k, err
}

func (p *Postgres) IDPasskeys(ctx context.Context, personID string) ([]IDPasskey, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+idPasskeyColumns+` FROM ento_id_passkeys WHERE person_id = $1 ORDER BY created_at, name`, personID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IDPasskey
	for rows.Next() {
		k, err := scanIDPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (p *Postgres) IDPasskey(ctx context.Context, credentialID []byte) (IDPasskey, error) {
	return scanIDPasskey(p.pool.QueryRow(ctx, `SELECT `+idPasskeyColumns+` FROM ento_id_passkeys WHERE credential_id = $1`, credentialID))
}

func (p *Postgres) AddIDPasskey(ctx context.Context, k IDPasskey) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO ento_id_passkeys (`+idPasskeyColumns+`) VALUES ($1, $2, $3, $4, $5, $6)`,
		k.CredentialID, k.PersonID, k.Name, k.Credential, k.CreatedAt, nullTime(k.LastUsed))
	if isUniqueViolation(err) {
		return ErrExists
	}
	if isForeignKeyViolation(err) {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) UseIDPasskey(ctx context.Context, credentialID, credential []byte, at time.Time) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		var person string
		err := tx.QueryRow(ctx, `UPDATE ento_id_passkeys SET credential = $2, last_used = $3 WHERE credential_id = $1 RETURNING person_id`,
			credentialID, credential, at).Scan(&person)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE ento_id_people SET last_sign_in = $2 WHERE id = $1`, person, at)
		return err
	})
}

func (p *Postgres) DeleteIDPasskey(ctx context.Context, personID string, credentialID []byte) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM ento_id_passkeys WHERE person_id = $1 AND credential_id = $2`, personID, credentialID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) IDGroups(ctx context.Context) ([]IDGroup, error) {
	rows, err := p.pool.Query(ctx, `SELECT name, kind, signin FROM ento_id_groups ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IDGroup
	for rows.Next() {
		var g IDGroup
		if err := rows.Scan(&g.Name, &g.Kind, &g.Signin); err != nil {
			return nil, err
		}
		if len(g.Signin) == 0 {
			g.Signin = nil
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (p *Postgres) PutIDGroup(ctx context.Context, g IDGroup) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO ento_id_groups (name, kind, signin) VALUES ($1, $2, $3)
		ON CONFLICT (name) DO UPDATE SET kind = EXCLUDED.kind, signin = EXCLUDED.signin`, g.Name, g.Kind, nonNil(g.Signin))
	return err
}

func (p *Postgres) DeleteIDGroup(ctx context.Context, name string) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM ento_id_groups WHERE name = $1`, name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx, `UPDATE ento_id_people SET groups = array_remove(groups, $1) WHERE $1 = ANY (groups)`, name)
		return err
	})
}

func (p *Postgres) PutIDState(ctx context.Context, s IDState) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO ento_id_state (key, kind, person, data, expires_at) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (key) DO UPDATE SET kind = EXCLUDED.kind, person = EXCLUDED.person, data = EXCLUDED.data,
		expires_at = EXCLUDED.expires_at`, s.Key, s.Kind, s.Person, s.Data, s.ExpiresAt)
	return err
}

func scanIDState(row pgx.Row, now time.Time) (IDState, error) {
	var s IDState
	err := row.Scan(&s.Key, &s.Kind, &s.Person, &s.Data, &s.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !now.Before(s.ExpiresAt) {
		return IDState{}, ErrNotFound
	}
	return s, err
}

func (p *Postgres) IDState(ctx context.Context, key string, now time.Time) (IDState, error) {
	return scanIDState(p.pool.QueryRow(ctx, `SELECT key, kind, person, data, expires_at FROM ento_id_state WHERE key = $1`, key), now)
}

func (p *Postgres) TakeIDState(ctx context.Context, key string, now time.Time) (IDState, error) {
	return scanIDState(p.pool.QueryRow(ctx, `DELETE FROM ento_id_state WHERE key = $1 RETURNING key, kind, person, data, expires_at`, key), now)
}

func (p *Postgres) DeleteIDStates(ctx context.Context, person, kind string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM ento_id_state WHERE person = $1 AND ($2 = '' OR kind = $2)`, person, kind)
	return err
}

func (p *Postgres) ExpireIDStates(ctx context.Context, now time.Time) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM ento_id_state WHERE expires_at <= $1`, now)
	return err
}
