package store

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"entowire.com/ento/internal/ipam"
	"entowire.com/ento/internal/names"
)

// NotifyChannel is the PostgreSQL channel notified after every change.
const NotifyChannel = "ento_changes"

const schema = `
CREATE TABLE IF NOT EXISTS ento_settings (
	key   text PRIMARY KEY,
	value text NOT NULL
);
CREATE TABLE IF NOT EXISTS ento_state (
	id      int PRIMARY KEY CHECK (id = 1),
	version bigint NOT NULL
);
INSERT INTO ento_state (id, version) VALUES (1, 1) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS ento_control_nodes (
	name       text PRIMARY KEY,
	public_key text NOT NULL UNIQUE,
	endpoint   text NOT NULL,
	address    text NOT NULL UNIQUE,
	last_seen  timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS ento_peers (
	id         bigserial PRIMARY KEY,
	public_key text NOT NULL UNIQUE,
	address    text NOT NULL UNIQUE,
	hostname   text NOT NULL,
	os         text NOT NULL,
	approved   boolean NOT NULL,
	admin      boolean NOT NULL,
	groups     text[] NOT NULL,
	endpoint   text NOT NULL DEFAULT '',
	created_at timestamptz NOT NULL,
	last_seen  timestamptz
);
CREATE TABLE IF NOT EXISTS ento_tokens (
	id            bigserial PRIMARY KEY,
	public_key    text NOT NULL UNIQUE,
	preshared_key text NOT NULL,
	temp_address  text NOT NULL,
	groups        text[] NOT NULL,
	approve       boolean NOT NULL,
	admin         boolean NOT NULL,
	created_at    timestamptz NOT NULL,
	expires_at    timestamptz NOT NULL,
	redeemed_at   timestamptz
);
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS user_id text NOT NULL DEFAULT '';
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS user_name text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS ento_policies (
	id          bigserial PRIMARY KEY,
	source      text NOT NULL,
	destination text NOT NULL,
	UNIQUE (source, destination)
);
ALTER TABLE ento_tokens ADD COLUMN IF NOT EXISTS authority text NOT NULL DEFAULT '';
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS authority text NOT NULL DEFAULT '';
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS approved_until timestamptz;
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS login_at timestamptz;
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS suspended boolean NOT NULL DEFAULT false;
ALTER TABLE ento_tokens ADD COLUMN IF NOT EXISTS created_by text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS ento_authorities (
	name            text PRIMARY KEY,
	public_key      text NOT NULL,
	groups          text[] NOT NULL,
	max_ttl_seconds bigint NOT NULL,
	token_id        bigint NOT NULL,
	created_at      timestamptz NOT NULL
);
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS reported_hostname text NOT NULL DEFAULT '';
ALTER TABLE ento_authorities ADD COLUMN IF NOT EXISTS suspended boolean NOT NULL DEFAULT false;
ALTER TABLE ento_tokens ADD COLUMN IF NOT EXISTS name text NOT NULL DEFAULT '';
ALTER TABLE ento_tokens ADD COLUMN IF NOT EXISTS replace_name boolean NOT NULL DEFAULT false;
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS operator boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS ento_links (
	name         text PRIMARY KEY,
	private_key  text NOT NULL,
	token        text NOT NULL DEFAULT '',
	groups       text[] NOT NULL,
	grant_groups text[] NOT NULL,
	ttl_seconds  bigint NOT NULL,
	created_at   timestamptz NOT NULL
);
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS authority_device text NOT NULL DEFAULT '';
ALTER TABLE ento_authorities ADD COLUMN IF NOT EXISTS max_devices integer NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS ento_link_keys (
	link       text NOT NULL REFERENCES ento_links (name) ON DELETE CASCADE,
	peer_id    bigint NOT NULL REFERENCES ento_peers (id) ON DELETE CASCADE,
	public_key text NOT NULL,
	updated_at timestamptz NOT NULL,
	PRIMARY KEY (link, peer_id)
);
CREATE TABLE IF NOT EXISTS ento_admin_sessions (
	hash       text PRIMARY KEY,
	peer_id    bigint NOT NULL REFERENCES ento_peers (id) ON DELETE CASCADE,
	code       text NOT NULL,
	browser    text NOT NULL,
	approved   boolean NOT NULL,
	created_at timestamptz NOT NULL,
	expires_at timestamptz NOT NULL,
	last_used  timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS ento_sso_tokens (
	peer_id    bigint PRIMARY KEY REFERENCES ento_peers (id) ON DELETE CASCADE,
	subject    text NOT NULL,
	token      text NOT NULL,
	next_check timestamptz NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ento_admin_sessions_pending ON ento_admin_sessions (peer_id, code) WHERE NOT approved;
-- 0.49: the person of a session opened by signing in on the page.
ALTER TABLE ento_admin_sessions ADD COLUMN IF NOT EXISTS person text NOT NULL DEFAULT '';
ALTER TABLE ento_policies ADD COLUMN IF NOT EXISTS posture text[] NOT NULL DEFAULT '{}';
ALTER TABLE ento_policies ADD COLUMN IF NOT EXISTS one_way boolean NOT NULL DEFAULT false;
ALTER TABLE ento_policies ADD COLUMN IF NOT EXISTS ports text[] NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS ento_posture_checks (
	name            text PRIMARY KEY,
	disk_encryption boolean NOT NULL,
	firewall        boolean NOT NULL,
	secure_boot     boolean NOT NULL,
	min_os          jsonb NOT NULL DEFAULT '{}',
	max_age_seconds bigint NOT NULL,
	created_at      timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS ento_posture (
	peer_id     bigint PRIMARY KEY REFERENCES ento_peers (id) ON DELETE CASCADE,
	facts       jsonb,
	reported_at timestamptz,
	results     jsonb
);
ALTER TABLE ento_posture ADD COLUMN IF NOT EXISTS results_at timestamptz;
ALTER TABLE ento_posture_checks ADD COLUMN IF NOT EXISTS antimalware boolean NOT NULL DEFAULT false;
ALTER TABLE ento_posture_checks ADD COLUMN IF NOT EXISTS max_patch_age jsonb NOT NULL DEFAULT '{}';
ALTER TABLE ento_links ADD COLUMN IF NOT EXISTS posture text[] NOT NULL DEFAULT '{}';
CREATE TABLE IF NOT EXISTS ento_link_posture (
	link       text NOT NULL REFERENCES ento_links (name) ON DELETE CASCADE,
	peer_id    bigint NOT NULL REFERENCES ento_peers (id) ON DELETE CASCADE,
	failing    text NOT NULL,
	changed_at timestamptz NOT NULL,
	PRIMARY KEY (link, peer_id)
);
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS user_login text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS ento_approvals (
	id          text PRIMARY KEY,
	requester   bigint NOT NULL REFERENCES ento_peers (id) ON DELETE CASCADE,
	user_id     text NOT NULL,
	login       text NOT NULL,
	service     text NOT NULL,
	number      integer NOT NULL,
	choices     integer[] NOT NULL,
	created_at  timestamptz NOT NULL,
	expires_at  timestamptz NOT NULL,
	state       text NOT NULL,
	answered_by bigint,
	answered_at timestamptz
);
CREATE INDEX IF NOT EXISTS ento_approvals_pending ON ento_approvals (user_id) WHERE state = 'pending';
ALTER TABLE ento_approvals ADD COLUMN IF NOT EXISTS boot_id text NOT NULL DEFAULT '';
CREATE TABLE IF NOT EXISTS ento_routes (
	name       text PRIMARY KEY,
	networks   text[] NOT NULL,
	via        text NOT NULL,
	created_at timestamptz NOT NULL,
	created_by text NOT NULL
);
ALTER TABLE ento_routes ADD COLUMN IF NOT EXISTS exit boolean NOT NULL DEFAULT false;
ALTER TABLE ento_routes ADD COLUMN IF NOT EXISTS use_by_default boolean NOT NULL DEFAULT false;
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS person_approved boolean NOT NULL DEFAULT false;
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS person_admin boolean NOT NULL DEFAULT false;
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS person_operator boolean NOT NULL DEFAULT false;
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS person_groups text[] NOT NULL DEFAULT '{}';
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS person_active boolean NOT NULL DEFAULT false;
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS person_since timestamptz;
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS person_activity_at timestamptz;
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS person_reports boolean NOT NULL DEFAULT false;
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS boot_id text NOT NULL DEFAULT '';
-- 0.27: approved, admin, operator and groups are the machine layer. Before, a device bound to a
-- person by single sign-on had its person's rights there (a session's): they move to the person
-- layer once (layered marks rows already in the new form; rows made later are).
ALTER TABLE ento_peers ADD COLUMN IF NOT EXISTS layered boolean NOT NULL DEFAULT false;
ALTER TABLE ento_peers ALTER COLUMN layered SET DEFAULT true;
UPDATE ento_peers SET person_approved = approved, person_admin = admin, person_operator = operator,
	person_groups = groups, person_active = approved, person_since = login_at,
	person_activity_at = COALESCE(last_seen, login_at), approved = false, admin = false, operator = false,
	groups = '{}', layered = true
	WHERE NOT layered AND user_id <> '' AND authority = '';
UPDATE ento_peers SET layered = true WHERE NOT layered;
CREATE TABLE IF NOT EXISTS ento_dns_records (
	name       text PRIMARY KEY,
	address    text NOT NULL,
	created_at timestamptz NOT NULL,
	created_by text NOT NULL
);
CREATE TABLE IF NOT EXISTS ento_update_policy (
	id          int PRIMARY KEY CHECK (id = 1),
	mode        text NOT NULL CHECK (mode IN ('auto', 'approve', 'off')),
	approved    text NOT NULL DEFAULT '',
	first_group text NOT NULL DEFAULT '',
	first_hours int NOT NULL DEFAULT 0,
	set_by      text NOT NULL,
	set_at      timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS ento_release_offers (
	version    text PRIMARY KEY,
	offered_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS ento_dns_forwards (
	zone       text PRIMARY KEY,
	servers    text[] NOT NULL,
	created_at timestamptz NOT NULL,
	created_by text NOT NULL
);
CREATE TABLE IF NOT EXISTS ento_hwkeys (
	peer_id        bigint PRIMARY KEY REFERENCES ento_peers (id) ON DELETE CASCADE,
	kind           text NOT NULL,
	public_key     text NOT NULL,
	bound_at       timestamptz NOT NULL,
	seen_at        timestamptz,
	unsigned_since timestamptz,
	rotate         boolean NOT NULL DEFAULT false,
	rotated_at     timestamptz
);
CREATE TABLE IF NOT EXISTS ento_signin_codes (
	hash         text PRIMARY KEY,
	peer_id      bigint NOT NULL REFERENCES ento_peers (id) ON DELETE CASCADE,
	person_since timestamptz NOT NULL,
	client_id    text NOT NULL,
	redirect_uri text NOT NULL,
	nonce        text NOT NULL,
	challenge    text NOT NULL,
	expires_at   timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS ento_signin_use (
	peer_id      bigint PRIMARY KEY REFERENCES ento_peers (id) ON DELETE CASCADE,
	person_since timestamptz NOT NULL,
	at           timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS ento_checkins (
	peer_id      bigint PRIMARY KEY REFERENCES ento_peers (id) ON DELETE CASCADE,
	cur          text NOT NULL,
	prev         text NOT NULL,
	fingerprint  text NOT NULL,
	endpoint     text NOT NULL,
	at           timestamptz,
	suspected    text NOT NULL,
	suspected_at timestamptz
);
`

// Postgres is a Store backed by PostgreSQL, shared by all control nodes of a deployment.
type Postgres struct {
	pool  *pgxpool.Pool
	space ipam.Space
}

// OpenPostgres connects, creates the schema if needed and checks that the database belongs to a
// deployment with the same overlay network.
func OpenPostgres(ctx context.Context, dsn string, space ipam.Space) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.DialFunc = dialDB
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	p := &Postgres{pool: pool, space: space}
	if err := p.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}

func (p *Postgres) migrate(ctx context.Context) error {
	if _, err := p.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	var network string
	err := p.pool.QueryRow(ctx,
		`INSERT INTO ento_settings (key, value) VALUES ('network', $1)
		 ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING value`,
		p.space.Prefix.String()).Scan(&network)
	if err != nil {
		return err
	}
	if network != p.space.Prefix.String() {
		return fmt.Errorf("database belongs to overlay network %s, not %s", network, p.space.Prefix)
	}
	return p.migrateNames(ctx)
}

// migrateNames gives devices enrolled before names were managed (ento 0.9.0), when a name was
// whatever the device reported, valid and unique names. They keep them as if an administrator had
// chosen them, since they were approved under them: only the characters are cleaned up, and
// duplicates get a counter. The unique index it creates marks the migration done.
func (p *Postgres) migrateNames(ctx context.Context) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// Serialised with every write, and with another control node migrating at the same time.
		if _, err := tx.Exec(ctx, `SELECT version FROM ento_state WHERE id = 1 FOR UPDATE`); err != nil {
			return err
		}
		var done bool
		if err := tx.QueryRow(ctx, `SELECT to_regclass('ento_peers_hostname_key') IS NOT NULL`).Scan(&done); err != nil || done {
			return err
		}
		type row struct {
			id   int64
			name string
		}
		rows, err := tx.Query(ctx, `SELECT id, hostname FROM ento_peers ORDER BY id`)
		if err != nil {
			return err
		}
		var all []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.name); err != nil {
				rows.Close()
				return err
			}
			all = append(all, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		taken, changed := map[string]bool{}, false
		for _, r := range all {
			name, _ := names.Free("", names.Base(r.name), func(n string) (bool, error) { return taken[n], nil })
			taken[name] = true
			changed = changed || name != r.name
			if _, err := tx.Exec(ctx, `UPDATE ento_peers SET hostname = $2, reported_hostname = $3 WHERE id = $1`,
				r.id, name, names.Reported(r.name)); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `CREATE UNIQUE INDEX ento_peers_hostname_key ON ento_peers (hostname)`); err != nil {
			return err
		}
		if !changed {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE ento_state SET version = version + 1 WHERE id = 1`); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `SELECT pg_notify($1, '')`, NotifyChannel)
		return err
	})
}

// nameHolder returns who has or reserves a device name: a device, or a token that can still be
// used (other than exceptToken). It returns nil if the name is free.
func nameHolder(ctx context.Context, tx pgx.Tx, name string, now time.Time, exceptToken int64) (*NameTakenError, error) {
	h := &NameTakenError{Name: name}
	err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT id FROM ento_peers WHERE hostname = $1), 0),
		COALESCE((SELECT min(id) FROM ento_tokens WHERE name = $1 AND redeemed_at IS NULL AND expires_at > $2 AND id <> $3), 0)`,
		name, now, exceptToken).Scan(&h.PeerID, &h.TokenID)
	if err != nil || (h.PeerID == 0 && h.TokenID == 0) {
		return nil, err
	}
	return h, nil
}

// Pool exposes the connection pool (used to LISTEN for changes).
func (p *Postgres) Pool() *pgxpool.Pool { return p.pool }

func (p *Postgres) Close() error { p.pool.Close(); return nil }

// write runs fn in a transaction serialised on the state row, then bumps the version and notifies
// the other control nodes if fn reports a change.
func (p *Postgres) write(ctx context.Context, fn func(tx pgx.Tx) (changed bool, err error)) error {
	return pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT version FROM ento_state WHERE id = 1 FOR UPDATE`); err != nil {
			return err
		}
		changed, err := fn(tx)
		if err != nil || !changed {
			return err
		}
		return bumpVersion(ctx, tx)
	})
}

// bumpVersion makes a new state version and tells the other control nodes.
func bumpVersion(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `UPDATE ento_state SET version = version + 1 WHERE id = 1`); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT pg_notify($1, '')`, NotifyChannel)
	return err
}

func (p *Postgres) Version(ctx context.Context) (int64, error) {
	var v int64
	err := p.pool.QueryRow(ctx, `SELECT version FROM ento_state WHERE id = 1`).Scan(&v)
	return v, err
}

func isUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (p *Postgres) ControlNodeSeen(ctx context.Context, name string, at time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE ento_control_nodes SET last_seen = $2 WHERE name = $1`, name, at)
	return err
}

func (p *Postgres) RegisterControlNode(ctx context.Context, n ControlNode) (ControlNode, error) {
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		var deviceKey bool // a device's or a token's key is never a control node's
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ento_peers WHERE public_key = $1)
			OR EXISTS (SELECT 1 FROM ento_tokens WHERE public_key = $1)`, n.PublicKey.String()).Scan(&deviceKey); err != nil {
			return false, err
		}
		if deviceKey {
			return false, ErrKeyInUse
		}
		var oldKey, oldEndpoint, oldAddress string
		err := tx.QueryRow(ctx, `SELECT public_key, endpoint, address FROM ento_control_nodes WHERE name = $1`,
			n.Name).Scan(&oldKey, &oldEndpoint, &oldAddress)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			used, err := usedAddresses(ctx, tx, `SELECT address FROM ento_control_nodes`)
			if err != nil {
				return false, err
			}
			if n.Address, err = ipam.FirstFree(p.space.ControlAddresses(), used); err != nil {
				return false, err
			}
			_, err = tx.Exec(ctx, `INSERT INTO ento_control_nodes (name, public_key, endpoint, address, last_seen)
				VALUES ($1, $2, $3, $4, $5)`, n.Name, n.PublicKey.String(), n.Endpoint, n.Address.String(), n.LastSeen)
			if isUniqueViolation(err) {
				return false, ErrKeyInUse
			}
			return true, err
		case err != nil:
			return false, err
		}
		n.Address = netip.MustParseAddr(oldAddress)
		_, err = tx.Exec(ctx, `UPDATE ento_control_nodes SET public_key = $2, endpoint = $3, last_seen = $4 WHERE name = $1`,
			n.Name, n.PublicKey.String(), n.Endpoint, n.LastSeen)
		if isUniqueViolation(err) {
			return false, ErrKeyInUse
		}
		return err == nil && (oldKey != n.PublicKey.String() || oldEndpoint != n.Endpoint), err
	})
	return n, err
}

func (p *Postgres) ControlNodes(ctx context.Context) ([]ControlNode, error) {
	rows, err := p.pool.Query(ctx, `SELECT name, public_key, endpoint, address, last_seen FROM ento_control_nodes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ControlNode
	for rows.Next() {
		var n ControlNode
		var key, addr string
		if err := rows.Scan(&n.Name, &key, &n.Endpoint, &addr, &n.LastSeen); err != nil {
			return nil, err
		}
		if n.PublicKey, err = wgtypes.ParseKey(key); err != nil {
			return nil, err
		}
		n.Address = netip.MustParseAddr(addr)
		out = append(out, n)
	}
	sortControls(out)
	return out, rows.Err()
}

func (p *Postgres) CreateToken(ctx context.Context, t Token) (Token, error) {
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		var err error
		t, err = p.createToken(ctx, tx, t)
		return err == nil, err
	})
	return t, err
}

func (p *Postgres) createToken(ctx context.Context, tx pgx.Tx, t Token) (Token, error) {
	t.CreatedAt = time.Now()
	if t.Name != "" {
		h, err := nameHolder(ctx, tx, t.Name, t.CreatedAt, 0)
		switch {
		case err != nil:
			return t, err
		case h == nil:
		case h.TokenID != 0:
			return t, &NameTakenError{Name: t.Name, TokenID: h.TokenID}
		case !t.Replace:
			return t, &NameTakenError{Name: t.Name, PeerID: h.PeerID}
		}
	}
	used, err := usedAddresses(ctx, tx,
		`SELECT temp_address FROM ento_tokens WHERE redeemed_at IS NULL AND expires_at > now()`)
	if err != nil {
		return t, err
	}
	switch {
	case t.TempAddress.IsValid(): // asked for (enrollment by words derives it)
		if !p.space.IsEnrollment(t.TempAddress) || used[t.TempAddress] {
			return t, ErrAddressInUse
		}
	default:
		if t.TempAddress, err = ipam.FirstFree(p.space.EnrollmentAddresses(), used); err != nil {
			return t, err
		}
	}
	err = tx.QueryRow(ctx, `INSERT INTO ento_tokens
		(public_key, preshared_key, temp_address, groups, approve, admin, created_at, expires_at, authority, created_by,
		 name, replace_name)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id`,
		t.PublicKey.String(), t.PresharedKey.String(), t.TempAddress.String(), nonNil(t.Groups),
		t.Approve, t.Admin, t.CreatedAt, t.ExpiresAt, t.Authority, t.CreatedBy, t.Name, t.Replace).Scan(&t.ID)
	if isUniqueViolation(err) {
		return t, ErrKeyInUse
	}
	return t, err
}

func (p *Postgres) ActiveTokens(ctx context.Context, now time.Time) ([]Token, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, public_key, preshared_key, temp_address, groups, approve, admin,
		created_at, expires_at, authority, created_by, name, replace_name
		FROM ento_tokens WHERE redeemed_at IS NULL AND expires_at > $1 ORDER BY id`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		var t Token
		var key, psk, addr string
		if err := rows.Scan(&t.ID, &key, &psk, &addr, &t.Groups, &t.Approve, &t.Admin, &t.CreatedAt, &t.ExpiresAt,
			&t.Authority, &t.CreatedBy, &t.Name, &t.Replace); err != nil {
			return nil, err
		}
		if t.PublicKey, err = wgtypes.ParseKey(key); err != nil {
			return nil, err
		}
		if t.PresharedKey, err = wgtypes.ParseKey(psk); err != nil {
			return nil, err
		}
		t.TempAddress = netip.MustParseAddr(addr)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *Postgres) DeleteToken(ctx context.Context, id int64) error {
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `DELETE FROM ento_tokens WHERE id = $1 AND redeemed_at IS NULL AND authority = ''`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return false, ErrNotFound
		}
		return true, err
	})
}

func (p *Postgres) Redeem(ctx context.Context, temp netip.Addr, key wgtypes.Key, hostname, os string, now time.Time, grant *Grant) (Peer, error) {
	var peer Peer
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		var tokenID int64
		var groups []string
		var approve, admin, replace bool
		var authority, name string
		err := tx.QueryRow(ctx, `SELECT id, groups, approve, admin, authority, name, replace_name FROM ento_tokens
			WHERE temp_address = $1 AND redeemed_at IS NULL AND expires_at > $2`, temp.String(), now).
			Scan(&tokenID, &groups, &approve, &admin, &authority, &name, &replace)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrTokenUnusable
		}
		if err != nil {
			return false, err
		}
		if (authority != "") != (grant != nil) || (grant != nil && grant.Authority != authority) {
			return false, ErrTokenUnusable
		}
		peer = Peer{PublicKey: key, ReportedHostname: names.Reported(hostname), OS: os, CreatedAt: now,
			Machine: Rights{Approved: approve, Admin: admin, Groups: nonNil(groups)}}
		if grant != nil && grant.Hostname != "" {
			peer.ReportedHostname = names.Reported(grant.Hostname)
		}
		var addr netip.Addr // the replaced device's, if any
		// A key already enrolled (a retried redeem) is refused before anything is replaced, and so
		// is a control node's or a token's key: a device holding one would take that peer's place
		// in the control nodes' WireGuard and cut agents off.
		var inUse bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ento_peers WHERE public_key = $1)
			OR EXISTS (SELECT 1 FROM ento_control_nodes WHERE public_key = $1)
			OR EXISTS (SELECT 1 FROM ento_tokens WHERE public_key = $1)`, key.String()).Scan(&inUse); err != nil {
			return false, err
		}
		if inUse {
			return false, ErrKeyInUse
		}
		if grant != nil {
			// One membership per device of the authority: a new key replaces the previous one
			// (deleted first, which frees its name for the new membership).
			if grant.DeviceID != "" {
				// A suspended membership is not replaced: the network's administrators excluded
				// that device, and a new key must not undo it.
				var suspended bool
				err := tx.QueryRow(ctx, `SELECT suspended FROM ento_peers WHERE authority = $1 AND authority_device = $2
					ORDER BY id LIMIT 1 FOR UPDATE`, grant.Authority, grant.DeviceID).Scan(&suspended)
				switch {
				case errors.Is(err, pgx.ErrNoRows):
				case err != nil:
					return false, err
				case suspended:
					return false, ErrMemberSuspended
				}
				var old string
				err = tx.QueryRow(ctx, `DELETE FROM ento_peers WHERE id = (SELECT id FROM ento_peers
					WHERE authority = $1 AND authority_device = $2 ORDER BY id LIMIT 1) RETURNING address`,
					grant.Authority, grant.DeviceID).Scan(&old)
				switch {
				case errors.Is(err, pgx.ErrNoRows):
				case err != nil:
					return false, err
				default:
					addr = netip.MustParseAddr(old)
				}
			}
			if grant.MaxDevices > 0 {
				var n int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM ento_peers WHERE authority = $1`, grant.Authority).Scan(&n); err != nil {
					return false, err
				}
				if n >= grant.MaxDevices {
					return false, &AuthorityFullError{Authority: grant.Authority, Max: grant.MaxDevices}
				}
			}
		}
		if name != "" {
			h, err := nameHolder(ctx, tx, name, now, tokenID)
			switch {
			case err != nil:
				return false, err
			case h == nil:
			case h.PeerID == 0 || !replace:
				return false, h
			default:
				var old string
				if err := tx.QueryRow(ctx, `DELETE FROM ento_peers WHERE id = $1 RETURNING address`, h.PeerID).Scan(&old); err != nil {
					return false, err
				}
				addr = netip.MustParseAddr(old)
			}
		} else {
			prefix := names.SelfPrefix
			if grant != nil {
				prefix = grant.Authority + "-"
			}
			name, err = names.Free(prefix, names.Base(peer.ReportedHostname), func(n string) (bool, error) {
				h, err := nameHolder(ctx, tx, n, now, 0)
				return h != nil, err
			})
			if err != nil {
				return false, err
			}
		}
		peer.Hostname = name
		if !addr.IsValid() {
			used, err := usedAddresses(ctx, tx, `SELECT address FROM ento_peers`)
			if err != nil {
				return false, err
			}
			if addr, err = p.space.FirstFreePeer(used); err != nil {
				return false, err
			}
		}
		peer.Address = addr
		var until *time.Time
		if grant != nil {
			peer.Machine = Rights{Approved: true, Groups: nonNil(grant.Groups)}
			peer.Authority, peer.UserName, peer.ApprovedUntil = grant.Authority, grant.UserName, grant.Until
			peer.AuthorityDevice = grant.DeviceID
			until = &peer.ApprovedUntil
		}
		peer.apply(PeerUpdate{})
		err = tx.QueryRow(ctx, `INSERT INTO ento_peers
			(public_key, address, hostname, reported_hostname, os, approved, admin, groups, created_at, authority, user_name,
			approved_until, authority_device)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id`,
			key.String(), addr.String(), peer.Hostname, peer.ReportedHostname, os, peer.Machine.Approved, peer.Machine.Admin, peer.Machine.Groups, now,
			peer.Authority, peer.UserName, until, peer.AuthorityDevice).Scan(&peer.ID)
		if isUniqueViolation(err) {
			return false, ErrKeyInUse
		}
		if err != nil {
			return false, err
		}
		if grant == nil { // authority tokens are reused
			_, err = tx.Exec(ctx, `UPDATE ento_tokens SET redeemed_at = $2 WHERE id = $1`, tokenID, now)
		}
		return true, err
	})
	return peer, err
}

const peerColumns = `id, public_key, address, hostname, reported_hostname, os, approved, admin, groups, endpoint, user_id, user_name, created_at, last_seen, authority, approved_until, login_at, suspended, operator, authority_device, user_login, person_approved, person_admin, person_operator, person_groups, person_active, person_since, person_activity_at, person_reports, boot_id`

// effectiveApproved is a device's approval in SQL (Peer.derive).
const effectiveApproved = `(NOT suspended AND NOT (groups && ARRAY['device:isolated','isolated']::text[]) AND (approved OR (person_active AND person_approved)))`

func scanPeer(row pgx.Row) (Peer, error) {
	var p Peer
	var key, addr string
	var lastSeen, until, loginAt, since, activity *time.Time
	if err := row.Scan(&p.ID, &key, &addr, &p.Hostname, &p.ReportedHostname, &p.OS, &p.Machine.Approved, &p.Machine.Admin,
		&p.Machine.Groups, &p.Endpoint, &p.User, &p.UserName, &p.CreatedAt, &lastSeen, &p.Authority, &until, &loginAt,
		&p.Suspended, &p.Machine.Operator, &p.AuthorityDevice, &p.UserLogin, &p.Person.Approved, &p.Person.Admin,
		&p.Person.Operator, &p.Person.Groups, &p.Person.Active, &since, &activity, &p.Person.Reports, &p.BootID); err != nil {
		return p, err
	}
	if since != nil {
		p.Person.Since = *since
	}
	if activity != nil {
		p.Person.ActivityAt = *activity
	}
	if until != nil {
		p.ApprovedUntil = *until
	}
	if loginAt != nil {
		p.LoginAt = *loginAt
	}
	var err error
	if p.PublicKey, err = wgtypes.ParseKey(key); err != nil {
		return p, err
	}
	p.Address = netip.MustParseAddr(addr)
	if lastSeen != nil {
		p.LastSeen = *lastSeen
	}
	p.apply(PeerUpdate{})
	return p, nil
}

func (p *Postgres) Peers(ctx context.Context) ([]Peer, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+peerColumns+` FROM ento_peers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Peer
	for rows.Next() {
		peer, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, peer)
	}
	return out, rows.Err()
}

func (p *Postgres) PeerByAddress(ctx context.Context, a netip.Addr) (Peer, error) {
	peer, err := scanPeer(p.pool.QueryRow(ctx, `SELECT `+peerColumns+` FROM ento_peers WHERE address = $1`, a.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return Peer{}, ErrNotFound
	}
	return peer, err
}

func (p *Postgres) PeerByPublicKey(ctx context.Context, key wgtypes.Key) (Peer, error) {
	peer, err := scanPeer(p.pool.QueryRow(ctx, `SELECT `+peerColumns+` FROM ento_peers WHERE public_key = $1`, key.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return Peer{}, ErrNotFound
	}
	return peer, err
}

func (p *Postgres) UpdatePeer(ctx context.Context, id int64, u PeerUpdate) (Peer, error) {
	var peer Peer
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		var err error
		peer, err = scanPeer(tx.QueryRow(ctx, `SELECT `+peerColumns+` FROM ento_peers WHERE id = $1 FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		if u.conflicts(peer) {
			return false, ErrChanged
		}
		if u.Hostname != nil && *u.Hostname != peer.Hostname {
			h, err := nameHolder(ctx, tx, *u.Hostname, time.Now(), 0)
			if err != nil {
				return false, err
			}
			if h != nil {
				return false, h
			}
		}
		peer.apply(u)
		return true, writePeer(ctx, tx, peer)
	})
	return peer, err
}

// writePeer stores a peer's changeable fields (its layers, not the effective rights derived from
// them).
func writePeer(ctx context.Context, tx pgx.Tx, peer Peer) error {
	opt := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		return &t
	}
	_, err := tx.Exec(ctx, `UPDATE ento_peers SET approved = $2, admin = $3, groups = $4, user_id = $5, user_name = $6,
		approved_until = $7, login_at = $8, suspended = $9, hostname = $10, operator = $11, authority_device = $12,
		user_login = $13, person_approved = $14, person_admin = $15, person_operator = $16, person_groups = $17,
		person_active = $18, person_since = $19, person_activity_at = $20, person_reports = $21, boot_id = $22 WHERE id = $1`,
		peer.ID, peer.Machine.Approved, peer.Machine.Admin, nonNil(peer.Machine.Groups), peer.User, peer.UserName,
		opt(peer.ApprovedUntil), opt(peer.LoginAt), peer.Suspended, peer.Hostname, peer.Machine.Operator, peer.AuthorityDevice,
		peer.UserLogin, peer.Person.Approved, peer.Person.Admin, peer.Person.Operator, nonNil(peer.Person.Groups),
		peer.Person.Active, opt(peer.Person.Since), opt(peer.Person.ActivityAt), peer.Person.Reports, peer.BootID)
	return err
}

func (p *Postgres) DeletePeer(ctx context.Context, id int64) error {
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `DELETE FROM ento_peers WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return false, ErrNotFound
		}
		return true, err
	})
}

func (p *Postgres) ObservePeer(ctx context.Context, key wgtypes.Key, endpoint string, at time.Time) (string, bool, error) {
	// Seen timestamps change constantly and must not wake every agent: update them without taking
	// the version lock, and only go through write() when the endpoint actually changed.
	var current string
	var approved bool
	err := p.pool.QueryRow(ctx, `UPDATE ento_peers SET last_seen = $2 WHERE public_key = $1 RETURNING endpoint, `+effectiveApproved,
		key.String(), at).Scan(&current, &approved)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrNotFound
	}
	if err != nil || endpoint == "" || endpoint == current {
		return current, false, err
	}
	if !approved {
		// An unapproved device is in no other device's map: its endpoint changes wake nobody and
		// take no lock (a device changing its address in a loop must not churn every agent).
		tag, err := p.pool.Exec(ctx, `UPDATE ento_peers SET endpoint = $2 WHERE public_key = $1 AND NOT `+effectiveApproved, key.String(), endpoint)
		if err == nil && tag.RowsAffected() == 1 {
			return current, true, nil
		}
		if err != nil {
			return current, false, err
		}
		// approved meanwhile: as below
	}
	var previous string
	changed := false
	err = p.write(ctx, func(tx pgx.Tx) (bool, error) {
		err := tx.QueryRow(ctx, `SELECT endpoint FROM ento_peers WHERE public_key = $1 FOR UPDATE`, key.String()).Scan(&previous)
		if err != nil || previous == endpoint {
			return false, err
		}
		_, err = tx.Exec(ctx, `UPDATE ento_peers SET endpoint = $2 WHERE public_key = $1`, key.String(), endpoint)
		changed = err == nil
		return changed, err
	})
	return previous, changed, err
}

func (p *Postgres) Policies(ctx context.Context) ([]Policy, error) {
	rows, err := p.pool.Query(ctx, `SELECT id, source, destination, posture, one_way, ports FROM ento_policies ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		var pol Policy
		if err := rows.Scan(&pol.ID, &pol.Source, &pol.Destination, &pol.Posture, &pol.OneWay, &pol.Ports); err != nil {
			return nil, err
		}
		pol.Posture, pol.Ports = nilIfEmpty(pol.Posture), nilIfEmpty(pol.Ports)
		out = append(out, pol)
	}
	return out, rows.Err()
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// missingCheck returns the first of the checks that does not exist. Within write(), which
// serialises it with DeletePostureCheck.
func missingCheck(ctx context.Context, tx pgx.Tx, checks []string) error {
	if len(checks) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT name FROM ento_posture_checks WHERE name = ANY ($1)`, checks)
	if err != nil {
		return err
	}
	have, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, name := range checks {
		if !slices.Contains(have, name) {
			return &NoSuchCheckError{Check: name}
		}
	}
	return nil
}

func (p *Postgres) AddPolicy(ctx context.Context, want Policy) (Policy, error) {
	pol := want
	existing := func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id, posture, one_way, ports FROM ento_policies WHERE source = $1 AND destination = $2`,
			want.Source, want.Destination).Scan(&pol.ID, &pol.Posture, &pol.OneWay, &pol.Ports)
		pol.Posture, pol.Ports = nilIfEmpty(pol.Posture), nilIfEmpty(pol.Ports)
		return err
	}
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		err := existing(tx)
		if err == nil {
			return false, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
		pol = want
		pol.Posture, pol.Ports = nilIfEmpty(want.Posture), nilIfEmpty(want.Ports)
		if err := missingCheck(ctx, tx, want.Posture); err != nil {
			return false, err
		}
		err = tx.QueryRow(ctx, `INSERT INTO ento_policies (source, destination, posture, one_way, ports) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (source, destination) DO NOTHING RETURNING id`, want.Source, want.Destination, nonNil(want.Posture),
			want.OneWay, nonNil(want.Ports)).Scan(&pol.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, existing(tx)
		}
		return true, err
	})
	return pol, err
}

func (p *Postgres) SetPolicyRules(ctx context.Context, id int64, oneWay bool, ports []string) (Policy, error) {
	var pol Policy
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		err := tx.QueryRow(ctx, `SELECT id, source, destination, posture, one_way, ports FROM ento_policies WHERE id = $1 FOR UPDATE`, id).
			Scan(&pol.ID, &pol.Source, &pol.Destination, &pol.Posture, &pol.OneWay, &pol.Ports)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		pol.Posture = nilIfEmpty(pol.Posture)
		if pol.OneWay == oneWay && slices.Equal(nilIfEmpty(pol.Ports), nilIfEmpty(ports)) {
			pol.Ports = nilIfEmpty(pol.Ports)
			return false, nil
		}
		pol.OneWay, pol.Ports = oneWay, nilIfEmpty(ports)
		_, err = tx.Exec(ctx, `UPDATE ento_policies SET one_way = $2, ports = $3 WHERE id = $1`, id, oneWay, nonNil(ports))
		return err == nil, err
	})
	return pol, err
}

func (p *Postgres) DeletePolicy(ctx context.Context, id int64) error {
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `DELETE FROM ento_policies WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return false, ErrNotFound
		}
		return true, err
	})
}

func (p *Postgres) SetPolicyPosture(ctx context.Context, id int64, posture []string) (Policy, error) {
	var pol Policy
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		var old []string
		err := tx.QueryRow(ctx, `SELECT id, source, destination, posture, one_way, ports FROM ento_policies WHERE id = $1 FOR UPDATE`, id).
			Scan(&pol.ID, &pol.Source, &pol.Destination, &old, &pol.OneWay, &pol.Ports)
		pol.Ports = nilIfEmpty(pol.Ports)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		pol.Posture = nilIfEmpty(posture)
		if slices.Equal(nilIfEmpty(old), pol.Posture) {
			return false, nil
		}
		if err := missingCheck(ctx, tx, posture); err != nil {
			return false, err
		}
		_, err = tx.Exec(ctx, `UPDATE ento_policies SET posture = $2 WHERE id = $1`, id, nonNil(posture))
		return err == nil, err
	})
	return pol, err
}

// Posture checks change nothing by themselves (a policy must require them), and reports only
// through their evaluation: only SetPostureResults goes through write().

func (p *Postgres) PostureChecks(ctx context.Context) ([]PostureCheck, error) {
	rows, err := p.pool.Query(ctx, `SELECT name, disk_encryption, firewall, secure_boot, antimalware, min_os, max_patch_age, max_age_seconds, created_at
		FROM ento_posture_checks ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PostureCheck
	for rows.Next() {
		var c PostureCheck
		var minOS map[string]string
		var patch map[string]int
		var maxAge int64
		if err := rows.Scan(&c.Name, &c.DiskEncryption, &c.Firewall, &c.SecureBoot, &c.Antimalware, &minOS, &patch, &maxAge, &c.CreatedAt); err != nil {
			return nil, err
		}
		if len(minOS) > 0 {
			c.MinOS = minOS
		}
		if len(patch) > 0 {
			c.MaxPatchAge = patch
		}
		c.MaxAge = time.Duration(maxAge) * time.Second
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) AddPostureCheck(ctx context.Context, c PostureCheck) (PostureCheck, error) {
	c.CreatedAt = time.Now()
	minOS, patch := c.MinOS, c.MaxPatchAge
	if minOS == nil {
		minOS = map[string]string{}
	}
	if patch == nil {
		patch = map[string]int{}
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO ento_posture_checks
		(name, disk_encryption, firewall, secure_boot, antimalware, min_os, max_patch_age, max_age_seconds, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		c.Name, c.DiskEncryption, c.Firewall, c.SecureBoot, c.Antimalware, minOS, patch, int64(c.MaxAge/time.Second), c.CreatedAt)
	if isUniqueViolation(err) {
		return PostureCheck{}, ErrExists
	}
	return c, err
}

func (p *Postgres) DeletePostureCheck(ctx context.Context, name string) error {
	// Serialised with policy and link changes (write(), whose AddPolicy, SetPolicyPosture,
	// CreateLink and SetLinkPosture check that their checks exist), so that nothing starts
	// requiring the check meanwhile.
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		rows, err := tx.Query(ctx, `SELECT id FROM ento_policies WHERE $1 = ANY (posture) ORDER BY id`, name)
		if err != nil {
			return false, err
		}
		users, err := pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return false, err
		}
		rows, err = tx.Query(ctx, `SELECT name FROM ento_links WHERE $1 = ANY (posture) ORDER BY name`, name)
		if err != nil {
			return false, err
		}
		links, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return false, err
		}
		if len(users) > 0 || len(links) > 0 {
			return false, &CheckInUseError{Check: name, Policies: users, Links: links}
		}
		tag, err := tx.Exec(ctx, `DELETE FROM ento_posture_checks WHERE name = $1`, name)
		if err == nil && tag.RowsAffected() == 0 {
			return false, ErrNotFound
		}
		return false, err
	})
}

func (p *Postgres) SetPostureReport(ctx context.Context, peerID int64, facts []byte, at time.Time, minGap time.Duration) error {
	// Conditional, so that the limit holds whichever control node a device reports to.
	tag, err := p.pool.Exec(ctx, `INSERT INTO ento_posture (peer_id, facts, reported_at) VALUES ($1, $2, $3)
		ON CONFLICT (peer_id) DO UPDATE SET facts = EXCLUDED.facts, reported_at = EXCLUDED.reported_at
		WHERE $4 <= 0 OR ento_posture.reported_at IS NULL OR ento_posture.reported_at <= EXCLUDED.reported_at - $4 * interval '1 microsecond'`,
		peerID, string(facts), at, minGap.Microseconds())
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" { // the device is gone
		return ErrNotFound
	}
	if err == nil && tag.RowsAffected() == 0 {
		return ErrTooSoon
	}
	return err
}

func (p *Postgres) PostureReports(ctx context.Context) ([]PostureReport, error) {
	rows, err := p.pool.Query(ctx, `SELECT peer_id, facts::text, reported_at, results, results_at FROM ento_posture ORDER BY peer_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PostureReport
	for rows.Next() {
		var r PostureReport
		var facts *string
		var at, resultsAt *time.Time
		if err := rows.Scan(&r.PeerID, &facts, &at, &r.Results, &resultsAt); err != nil {
			return nil, err
		}
		if resultsAt != nil {
			r.ResultsAt = *resultsAt
		}
		if facts != nil {
			r.Facts = []byte(*facts)
		}
		if at != nil {
			r.ReportedAt = *at
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) SetPostureResults(ctx context.Context, peerID int64, previous, results map[string]string) (bool, error) {
	if results == nil {
		results = map[string]string{}
	}
	applied := false
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		var stored map[string]string
		var exists bool
		err := tx.QueryRow(ctx, `SELECT results FROM ento_posture WHERE peer_id = $1 FOR UPDATE`, peerID).Scan(&stored)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return false, err
		default:
			exists = true
		}
		// Conditional on the stored evaluation, "none" (nil) included.
		if (stored == nil) != (previous == nil) || !maps.Equal(stored, previous) {
			return false, nil
		}
		if exists {
			_, err = tx.Exec(ctx, `UPDATE ento_posture SET results = $2,
				results_at = CASE WHEN results IS DISTINCT FROM $2 OR results_at IS NULL THEN now() ELSE results_at END
				WHERE peer_id = $1`, peerID, results)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO ento_posture (peer_id, results, results_at) VALUES ($1, $2, now())`, peerID, results)
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "23503" {
				return false, ErrNotFound
			}
		}
		if err != nil {
			return false, err
		}
		applied = true
		return !maps.Equal(stored, results), nil
	})
	return applied, err
}

func (p *Postgres) ExpirePeers(ctx context.Context, now time.Time) (int, error) {
	// Checked without the version lock first: this runs every few seconds on every control node.
	var due bool
	if err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ento_peers
		WHERE approved AND approved_until IS NOT NULL AND approved_until <= $1)`, now).Scan(&due); err != nil || !due {
		return 0, err
	}
	var n int
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `UPDATE ento_peers SET approved = false
			WHERE approved AND approved_until IS NOT NULL AND approved_until <= $1`, now)
		n = int(tag.RowsAffected())
		return err == nil && n > 0, err
	})
	return n, err
}

func (p *Postgres) EndIdleSessions(ctx context.Context, now time.Time, idle, max time.Duration) ([]Peer, error) {
	var due bool
	if err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ento_peers WHERE person_active AND user_id <> '')`).Scan(&due); err != nil || !due {
		return nil, err
	}
	var ended []Peer
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		ended = nil
		rows, err := tx.Query(ctx, `SELECT `+peerColumns+` FROM ento_peers WHERE person_active AND user_id <> '' FOR UPDATE`)
		if err != nil {
			return false, err
		}
		var open []Peer
		for rows.Next() {
			peer, err := scanPeer(rows)
			if err != nil {
				rows.Close()
				return false, err
			}
			open = append(open, peer)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return false, err
		}
		for _, peer := range open {
			if !PersonIdle(peer, now, idle, max) {
				continue
			}
			if _, err := tx.Exec(ctx, `UPDATE ento_peers SET person_active = false WHERE id = $1`, peer.ID); err != nil {
				return false, err
			}
			ended = append(ended, peer)
		}
		return len(ended) > 0, nil
	})
	return ended, err
}

func (p *Postgres) CreateAuthority(ctx context.Context, a Authority, t Token) (Authority, Token, error) {
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ento_authorities WHERE name = $1)`, a.Name).Scan(&exists); err != nil {
			return false, err
		}
		if exists {
			return false, ErrExists
		}
		t.Authority = a.Name
		var err error
		if t, err = p.createToken(ctx, tx, t); err != nil {
			return false, err
		}
		a.TokenID, a.CreatedAt = t.ID, t.CreatedAt
		_, err = tx.Exec(ctx, `INSERT INTO ento_authorities (name, public_key, groups, max_ttl_seconds, token_id, created_at, max_devices)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, a.Name, base64.StdEncoding.EncodeToString(a.PublicKey), nonNil(a.Groups),
			int64(a.MaxTTL/time.Second), a.TokenID, a.CreatedAt, a.MaxDevices)
		return true, err
	})
	return a, t, err
}

const authorityColumns = `name, public_key, groups, max_ttl_seconds, token_id, created_at, suspended, max_devices`

func scanAuthority(row pgx.Row) (Authority, error) {
	var a Authority
	var key string
	var ttl int64
	if err := row.Scan(&a.Name, &key, &a.Groups, &ttl, &a.TokenID, &a.CreatedAt, &a.Suspended, &a.MaxDevices); err != nil {
		return a, err
	}
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return a, fmt.Errorf("authority %s: corrupt public key", a.Name)
	}
	a.PublicKey, a.MaxTTL = b, time.Duration(ttl)*time.Second
	return a, nil
}

func (p *Postgres) Authorities(ctx context.Context) ([]Authority, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+authorityColumns+` FROM ento_authorities ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Authority
	for rows.Next() {
		a, err := scanAuthority(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) Authority(ctx context.Context, name string) (Authority, error) {
	a, err := scanAuthority(p.pool.QueryRow(ctx, `SELECT `+authorityColumns+` FROM ento_authorities WHERE name = $1`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Authority{}, ErrNotFound
	}
	return a, err
}

func (p *Postgres) DeleteAuthority(ctx context.Context, name string) error {
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		var tokenID int64
		err := tx.QueryRow(ctx, `DELETE FROM ento_authorities WHERE name = $1 RETURNING token_id`, name).Scan(&tokenID)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM ento_tokens WHERE id = $1`, tokenID); err != nil {
			return false, err
		}
		_, err = tx.Exec(ctx, `DELETE FROM ento_peers WHERE authority = $1`, name)
		return true, err
	})
}

func (p *Postgres) SuspendAuthority(ctx context.Context, name string, suspended bool) error {
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `UPDATE ento_authorities SET suspended = $2 WHERE name = $1`, name, suspended)
		if err == nil && tag.RowsAffected() == 0 {
			return false, ErrNotFound
		}
		if err != nil || !suspended {
			return err == nil, err
		}
		_, err = tx.Exec(ctx, `UPDATE ento_peers SET approved = false, approved_until = now() WHERE authority = $1`, name)
		return true, err
	})
}

func (p *Postgres) SetAuthorityLimit(ctx context.Context, name string, maxDevices int) error {
	tag, err := p.pool.Exec(ctx, `UPDATE ento_authorities SET max_devices = $2 WHERE name = $1`, name, maxDevices)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) RotateAuthorityToken(ctx context.Context, name string, t Token) (Token, error) {
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		var old int64
		err := tx.QueryRow(ctx, `SELECT token_id FROM ento_authorities WHERE name = $1 FOR UPDATE`, name).Scan(&old)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		t.Authority = name
		if t, err = p.createToken(ctx, tx, t); err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `UPDATE ento_authorities SET token_id = $2 WHERE name = $1`, name, t.ID); err != nil {
			return false, err
		}
		_, err = tx.Exec(ctx, `DELETE FROM ento_tokens WHERE id = $1`, old)
		return true, err
	})
	return t, err
}

// Links are only used by this network's own control plane (to sign credentials); they are not
// part of the network map, so changing them does not bump the version. Every statement changes
// only the columns it is about: control nodes of different versions share the table, and an older
// one must not drop what it does not know (posture).

func (p *Postgres) CreateLink(ctx context.Context, l Link) (Link, error) {
	l.CreatedAt = time.Now()
	l.Posture = nilIfEmpty(l.Posture)
	// Within write(), serialised with DeletePostureCheck (see missingCheck); no new version.
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		if err := missingCheck(ctx, tx, l.Posture); err != nil {
			return false, err
		}
		_, err := tx.Exec(ctx, `INSERT INTO ento_links (name, private_key, token, groups, grant_groups, ttl_seconds, created_at, posture)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, l.Name, base64.StdEncoding.EncodeToString(l.PrivateKey), l.Token,
			nonNil(l.Groups), nonNil(l.Grant), int64(l.TTL/time.Second), l.CreatedAt, nonNil(l.Posture))
		if isUniqueViolation(err) {
			return false, ErrExists
		}
		return false, err
	})
	if err != nil {
		return Link{}, err
	}
	return l, nil
}

const linkColumns = `name, private_key, token, groups, grant_groups, ttl_seconds, created_at, posture`

func scanLink(row pgx.Row) (Link, error) {
	var l Link
	var key string
	var ttl int64
	if err := row.Scan(&l.Name, &key, &l.Token, &l.Groups, &l.Grant, &ttl, &l.CreatedAt, &l.Posture); err != nil {
		return l, err
	}
	l.Posture = nilIfEmpty(l.Posture)
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return l, fmt.Errorf("link %s: corrupt private key", l.Name)
	}
	l.PrivateKey, l.TTL = b, time.Duration(ttl)*time.Second
	return l, nil
}

func (p *Postgres) Links(ctx context.Context) ([]Link, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+linkColumns+` FROM ento_links ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Link
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (p *Postgres) Link(ctx context.Context, name string) (Link, error) {
	l, err := scanLink(p.pool.QueryRow(ctx, `SELECT `+linkColumns+` FROM ento_links WHERE name = $1`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Link{}, ErrNotFound
	}
	return l, err
}

func (p *Postgres) SetLinkToken(ctx context.Context, name, token string) error {
	tag, err := p.pool.Exec(ctx, `UPDATE ento_links SET token = $2 WHERE name = $1`, name, token)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) SetLinkPosture(ctx context.Context, name string, posture []string) (Link, error) {
	var l Link
	err := p.write(ctx, func(tx pgx.Tx) (bool, error) {
		var err error
		l, err = scanLink(tx.QueryRow(ctx, `SELECT `+linkColumns+` FROM ento_links WHERE name = $1 FOR UPDATE`, name))
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		if slices.Equal(l.Posture, nilIfEmpty(posture)) {
			return false, nil
		}
		if err := missingCheck(ctx, tx, posture); err != nil {
			return false, err
		}
		l.Posture = nilIfEmpty(posture)
		if _, err := tx.Exec(ctx, `UPDATE ento_links SET posture = $2 WHERE name = $1`, name, nonNil(posture)); err != nil {
			return false, err
		}
		_, err = tx.Exec(ctx, `DELETE FROM ento_link_posture WHERE link = $1`, name)
		return false, err
	})
	return l, err
}

func (p *Postgres) SwapLinkPosture(ctx context.Context, link string, peerID int64, failing string) (string, error) {
	// Most calls change nothing (a renewal of a device that keeps passing): read first, and take the
	// lock only for a change.
	var stored string
	err := p.pool.QueryRow(ctx, `SELECT failing FROM ento_link_posture WHERE link = $1 AND peer_id = $2`, link, peerID).Scan(&stored)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return "", err
	}
	if stored == failing {
		return stored, nil
	}
	var previous string
	err = p.write(ctx, func(tx pgx.Tx) (bool, error) {
		err := tx.QueryRow(ctx, `SELECT failing FROM ento_link_posture WHERE link = $1 AND peer_id = $2`, link, peerID).Scan(&previous)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			previous = ""
		case err != nil:
			return false, err
		}
		if previous == failing {
			return false, nil
		}
		if failing == "" {
			_, err = tx.Exec(ctx, `DELETE FROM ento_link_posture WHERE link = $1 AND peer_id = $2`, link, peerID)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO ento_link_posture (link, peer_id, failing, changed_at) VALUES ($1, $2, $3, now())
				ON CONFLICT (link, peer_id) DO UPDATE SET failing = EXCLUDED.failing, changed_at = EXCLUDED.changed_at`, link, peerID, failing)
		}
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23503" { // the link or the device is gone
			return false, ErrNotFound
		}
		return false, err
	})
	return previous, err
}

func (p *Postgres) DeleteLink(ctx context.Context, name string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM ento_links WHERE name = $1`, name) // keys go with it
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) LinkKey(ctx context.Context, link string, peerID int64) (wgtypes.Key, error) {
	var s string
	err := p.pool.QueryRow(ctx, `SELECT public_key FROM ento_link_keys WHERE link = $1 AND peer_id = $2`, link, peerID).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return wgtypes.Key{}, ErrNotFound
	}
	if err != nil {
		return wgtypes.Key{}, err
	}
	return wgtypes.ParseKey(s)
}

func (p *Postgres) SetLinkKey(ctx context.Context, link string, peerID int64, key wgtypes.Key) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO ento_link_keys (link, peer_id, public_key, updated_at) VALUES ($1, $2, $3, now())
		ON CONFLICT (link, peer_id) DO UPDATE SET public_key = EXCLUDED.public_key, updated_at = EXCLUDED.updated_at`,
		link, peerID, key.String())
	return err
}

// Refresh tokens are not part of the network map either.

func (p *Postgres) SetSSOToken(ctx context.Context, t SSOToken) error {
	if t.Previous != "" {
		tag, err := p.pool.Exec(ctx, `UPDATE ento_sso_tokens SET subject = $2, token = $3, next_check = $4
			WHERE peer_id = $1 AND token = $5`, t.PeerID, t.Subject, t.Encrypted, t.NextCheck, t.Previous)
		if err == nil && tag.RowsAffected() == 0 {
			err = ErrChanged
		}
		return err
	}
	_, err := p.pool.Exec(ctx, `INSERT INTO ento_sso_tokens (peer_id, subject, token, next_check) VALUES ($1, $2, $3, $4)
		ON CONFLICT (peer_id) DO UPDATE SET subject = EXCLUDED.subject, token = EXCLUDED.token, next_check = EXCLUDED.next_check`,
		t.PeerID, t.Subject, t.Encrypted, t.NextCheck)
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" { // the device is gone
		return ErrNotFound
	}
	return err
}

func (p *Postgres) ClaimSSOTokens(ctx context.Context, now, next time.Time, limit int) ([]SSOToken, error) {
	rows, err := p.pool.Query(ctx, `UPDATE ento_sso_tokens SET next_check = $2 WHERE peer_id IN (
			SELECT peer_id FROM ento_sso_tokens WHERE next_check <= $1 ORDER BY next_check LIMIT $3 FOR UPDATE SKIP LOCKED)
		RETURNING peer_id, subject, token`, now, next, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SSOToken
	for rows.Next() {
		t := SSOToken{NextCheck: next}
		if err := rows.Scan(&t.PeerID, &t.Subject, &t.Encrypted); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *Postgres) DeleteSSOToken(ctx context.Context, peerID int64, token string) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM ento_sso_tokens WHERE peer_id = $1 AND ($2 = '' OR token = $2)`, peerID, token)
	if err == nil && token != "" && tag.RowsAffected() == 0 {
		err = ErrChanged
	}
	return err
}

func (p *Postgres) ForgetSSOTokens(ctx context.Context) ([]int64, error) {
	var ids []int64
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `DELETE FROM ento_sso_tokens RETURNING peer_id`)
		if err != nil {
			return err
		}
		ids, err = pgx.CollectRows(rows, pgx.RowTo[int64])
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM ento_settings WHERE key = $1`, SettingSSOTokenCanary)
		return err
	})
	slices.Sort(ids)
	return ids, err
}

func (p *Postgres) KeepSetting(ctx context.Context, key, value string) (string, error) {
	var stored string
	err := p.pool.QueryRow(ctx,
		`INSERT INTO ento_settings (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING value`, key, value).Scan(&stored)
	return stored, err
}

// Sessions of the admin interface are not part of the network map either.

func (p *Postgres) CreateUISession(ctx context.Context, u UISession) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO ento_admin_sessions (hash, peer_id, code, browser, approved, created_at, expires_at, last_used, person)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, u.Hash, u.PeerID, u.Code, u.Browser, u.Approved, u.CreatedAt, u.ExpiresAt, u.LastUsed, u.Person)
	if isUniqueViolation(err) {
		return ErrExists
	}
	return err
}

const uiSessionColumns = `hash, peer_id, code, browser, approved, created_at, expires_at, last_used, person`

func scanUISession(row pgx.Row) (UISession, error) {
	var u UISession
	err := row.Scan(&u.Hash, &u.PeerID, &u.Code, &u.Browser, &u.Approved, &u.CreatedAt, &u.ExpiresAt, &u.LastUsed, &u.Person)
	if errors.Is(err, pgx.ErrNoRows) {
		return UISession{}, ErrNotFound
	}
	return u, err
}

func (p *Postgres) UISession(ctx context.Context, hash string, now time.Time) (UISession, error) {
	return scanUISession(p.pool.QueryRow(ctx, `SELECT `+uiSessionColumns+` FROM ento_admin_sessions WHERE hash = $1 AND expires_at > $2`,
		hash, now))
}

func (p *Postgres) PendingUISessions(ctx context.Context, peerID int64, now time.Time) (int, error) {
	var n int
	err := p.pool.QueryRow(ctx, `SELECT count(*) FROM ento_admin_sessions WHERE peer_id = $1 AND NOT approved AND expires_at > $2`,
		peerID, now).Scan(&n)
	return n, err
}

func (p *Postgres) ApproveUISession(ctx context.Context, peerID int64, code string, now, expires time.Time) (UISession, error) {
	return scanUISession(p.pool.QueryRow(ctx, `UPDATE ento_admin_sessions SET approved = true, expires_at = $4, last_used = $3
		WHERE peer_id = $1 AND code = $2 AND NOT approved AND expires_at > $3 RETURNING `+uiSessionColumns, peerID, code, now, expires))
}

func (p *Postgres) TouchUISession(ctx context.Context, hash string, now time.Time) error {
	_, err := p.pool.Exec(ctx, `UPDATE ento_admin_sessions SET last_used = $2 WHERE hash = $1`, hash, now)
	return err
}

func (p *Postgres) DeleteUISessionsOf(ctx context.Context, peerID int64) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM ento_admin_sessions WHERE peer_id = $1`, peerID)
	return err
}

func (p *Postgres) DeleteUISession(ctx context.Context, hash string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM ento_admin_sessions WHERE hash = $1`, hash)
	return err
}

func (p *Postgres) ExpireUISessions(ctx context.Context, now time.Time) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM ento_admin_sessions WHERE expires_at <= $1`, now)
	return err
}

// The device sign-in provider's codes and records are not part of the network map either.

func (p *Postgres) CreateSignInCode(ctx context.Context, c SignInCode) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO ento_signin_codes (hash, peer_id, person_since, client_id, redirect_uri, nonce, challenge, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, c.Hash, c.PeerID, c.PersonSince, c.ClientID, c.RedirectURI, c.Nonce, c.Challenge, c.ExpiresAt)
	if isUniqueViolation(err) {
		return ErrExists
	}
	return err
}

func (p *Postgres) TakeSignInCode(ctx context.Context, hash string, now time.Time) (SignInCode, error) {
	var c SignInCode
	err := p.pool.QueryRow(ctx, `DELETE FROM ento_signin_codes WHERE hash = $1
		RETURNING hash, peer_id, person_since, client_id, redirect_uri, nonce, challenge, expires_at`, hash).
		Scan(&c.Hash, &c.PeerID, &c.PersonSince, &c.ClientID, &c.RedirectURI, &c.Nonce, &c.Challenge, &c.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !now.Before(c.ExpiresAt) {
		return SignInCode{}, ErrNotFound
	}
	return c, err
}

func (p *Postgres) ExpireSignInCodes(ctx context.Context, now time.Time) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM ento_signin_codes WHERE expires_at <= $1`, now)
	return err
}

func (p *Postgres) LastSignIn(ctx context.Context, peerID int64, since time.Time) (time.Time, error) {
	var at time.Time
	err := p.pool.QueryRow(ctx, `SELECT at FROM ento_signin_use WHERE peer_id = $1 AND person_since = $2`, peerID, since).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	return at, err
}

func (p *Postgres) RecordSignIn(ctx context.Context, peerID int64, since, at time.Time) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO ento_signin_use (peer_id, person_since, at) VALUES ($1, $2, $3)
		ON CONFLICT (peer_id) DO UPDATE SET person_since = EXCLUDED.person_since, at = EXCLUDED.at`, peerID, since, at)
	return err
}

func usedAddresses(ctx context.Context, tx pgx.Tx, query string) (map[netip.Addr]bool, error) {
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		used[netip.MustParseAddr(s)] = true
	}
	return used, rows.Err()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Listen signals on the returned channel whenever any control node commits a change. It reconnects
// on errors; callers should still poll as a fallback.
func (p *Postgres) Listen(ctx context.Context, logf func(string, ...any)) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		for ctx.Err() == nil {
			err := func() error {
				conn, err := p.pool.Acquire(ctx)
				if err != nil {
					return err
				}
				defer conn.Release()
				if _, err := conn.Exec(ctx, "LISTEN "+NotifyChannel); err != nil {
					return err
				}
				for {
					if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
						return err
					}
					select {
					case ch <- struct{}{}:
					default:
					}
				}
			}()
			if ctx.Err() == nil {
				logf("change notifications: %v (reconnecting)", err)
				time.Sleep(2 * time.Second)
			}
		}
	}()
	return ch
}

// Sign-in approvals change no network map: they are written without the version lock.

const approvalColumns = `id, requester, user_id, login, service, number, choices, created_at, expires_at, state, answered_by, answered_at, boot_id`

func scanApproval(row pgx.Row) (Approval, error) {
	var a Approval
	var by *int64
	var at *time.Time
	var choices []int32
	if err := row.Scan(&a.ID, &a.Requester, &a.User, &a.Login, &a.Service, &a.Number, &choices, &a.CreatedAt, &a.ExpiresAt,
		&a.State, &by, &at, &a.BootID); err != nil {
		return a, err
	}
	for _, c := range choices {
		a.Choices = append(a.Choices, int(c))
	}
	if by != nil {
		a.AnsweredBy = *by
	}
	if at != nil {
		a.AnsweredAt = *at
	}
	return a, nil
}

func (p *Postgres) CreateApproval(ctx context.Context, a Approval) error {
	_, err := p.pool.Exec(ctx, `INSERT INTO ento_approvals (id, requester, user_id, login, service, number, choices, created_at,
		expires_at, state, boot_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		a.ID, a.Requester, a.User, a.Login, a.Service, a.Number, a.Choices, a.CreatedAt, a.ExpiresAt, ApprovalPending, a.BootID)
	return err
}

func (p *Postgres) Approval(ctx context.Context, id string) (Approval, error) {
	a, err := scanApproval(p.pool.QueryRow(ctx, `SELECT `+approvalColumns+` FROM ento_approvals WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

func (p *Postgres) PendingApprovals(ctx context.Context, user string, now time.Time) ([]Approval, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+approvalColumns+` FROM ento_approvals
		WHERE user_id = $1 AND state = 'pending' AND expires_at > $2 ORDER BY created_at`, user, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (p *Postgres) AnyPendingApproval(ctx context.Context, now time.Time) (bool, error) {
	var any bool
	err := p.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ento_approvals WHERE state = 'pending' AND expires_at > $1)`, now).Scan(&any)
	return any, err
}

func (p *Postgres) FinishApproval(ctx context.Context, id, state string, by int64, at time.Time) (Approval, error) {
	var answeredBy *int64
	if by != 0 {
		answeredBy = &by
	}
	a, err := scanApproval(p.pool.QueryRow(ctx, `UPDATE ento_approvals SET state = $2, answered_by = $3, answered_at = $4
		WHERE id = $1 AND state = 'pending' RETURNING `+approvalColumns, id, state, answeredBy, at))
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err := p.Approval(ctx, id); err != nil {
			return a, err
		}
		return a, ErrChanged
	}
	return a, err
}

func (p *Postgres) CountApprovals(ctx context.Context, requester int64, user string, since time.Time) (int, int, error) {
	var byRequester, byUser int
	err := p.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE requester = $1), count(*) FILTER (WHERE user_id = $2)
		FROM ento_approvals WHERE created_at >= $3`, requester, user, since).Scan(&byRequester, &byUser)
	return byRequester, byUser, err
}

func (p *Postgres) DeleteApprovalsBefore(ctx context.Context, t time.Time) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM ento_approvals WHERE expires_at < $1`, t)
	return err
}

// Check-ins change no network map either.

const checkInColumns = `peer_id, cur, prev, fingerprint, endpoint, at, suspected, suspected_at`

func scanCheckIn(row pgx.Row) (CheckIn, error) {
	var c CheckIn
	var at, sat *time.Time
	if err := row.Scan(&c.PeerID, &c.Cur, &c.Prev, &c.Fingerprint, &c.Endpoint, &at, &c.Suspected, &sat); err != nil {
		return c, err
	}
	if at != nil {
		c.At = *at
	}
	if sat != nil {
		c.SuspectedAt = *sat
	}
	return c, nil
}

func (p *Postgres) UpdateCheckIn(ctx context.Context, peerID int64, fn func(c CheckIn, found bool) (CheckIn, error)) (CheckIn, error) {
	var out CheckIn
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// The device's row is the lock; a device without one locks its peer row, so two control
		// nodes cannot both create it.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM ento_peers WHERE id = $1 FOR UPDATE`, peerID); err != nil {
			return err
		}
		cur, err := scanCheckIn(tx.QueryRow(ctx, `SELECT `+checkInColumns+` FROM ento_checkins WHERE peer_id = $1 FOR UPDATE`, peerID))
		found := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if !found {
			cur = CheckIn{PeerID: peerID}
		}
		next, err := fn(cur, found)
		if err != nil {
			return err
		}
		next.PeerID = peerID
		_, err = tx.Exec(ctx, `INSERT INTO ento_checkins (`+checkInColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (peer_id) DO UPDATE SET cur = $2, prev = $3, fingerprint = $4, endpoint = $5, at = $6, suspected = $7,
			suspected_at = $8`, peerID, next.Cur, next.Prev, next.Fingerprint, next.Endpoint, nullTime(next.At), next.Suspected,
			nullTime(next.SuspectedAt))
		out = next
		return err
	})
	return out, err
}

// Hardware keys change no network map; a rotation does.

const hwKeyColumns = `peer_id, kind, public_key, bound_at, seen_at, unsigned_since, rotate, rotated_at`

func scanHWKey(row pgx.Row) (HWKey, error) {
	var k HWKey
	var seen, unsigned, rotated *time.Time
	if err := row.Scan(&k.PeerID, &k.Kind, &k.PublicKey, &k.BoundAt, &seen, &unsigned, &k.Rotate, &rotated); err != nil {
		return k, err
	}
	for _, f := range []struct {
		src *time.Time
		dst *time.Time
	}{{seen, &k.SeenAt}, {unsigned, &k.UnsignedSince}, {rotated, &k.RotatedAt}} {
		if f.src != nil {
			*f.dst = *f.src
		}
	}
	return k, nil
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (p *Postgres) UpdateHWKey(ctx context.Context, peerID int64, fn func(k HWKey, found bool) (HWKey, error)) (HWKey, error) {
	var out HWKey
	err := pgx.BeginFunc(ctx, p.pool, func(tx pgx.Tx) error {
		// The device's row is the lock, as for check-ins.
		var one int
		if err := tx.QueryRow(ctx, `SELECT 1 FROM ento_peers WHERE id = $1 FOR UPDATE`, peerID).Scan(&one); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		cur, err := scanHWKey(tx.QueryRow(ctx, `SELECT `+hwKeyColumns+` FROM ento_hwkeys WHERE peer_id = $1 FOR UPDATE`, peerID))
		found := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if !found {
			cur = HWKey{PeerID: peerID}
		}
		next, err := fn(cur, found)
		if err != nil {
			return err
		}
		next.PeerID = peerID
		if next.BoundAt.IsZero() {
			next.BoundAt = time.Now()
		}
		_, err = tx.Exec(ctx, `INSERT INTO ento_hwkeys (`+hwKeyColumns+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (peer_id) DO UPDATE SET kind = $2, public_key = $3, bound_at = $4, seen_at = $5, unsigned_since = $6,
			rotate = $7, rotated_at = $8`, peerID, next.Kind, next.PublicKey, next.BoundAt, nullTime(next.SeenAt),
			nullTime(next.UnsignedSince), next.Rotate, nullTime(next.RotatedAt))
		if err != nil {
			return err
		}
		out = next
		if next.Rotate != cur.Rotate { // the device's map says so
			return bumpVersion(ctx, tx)
		}
		return nil
	})
	return out, err
}

func (p *Postgres) HWKey(ctx context.Context, peerID int64) (HWKey, error) {
	k, err := scanHWKey(p.pool.QueryRow(ctx, `SELECT `+hwKeyColumns+` FROM ento_hwkeys WHERE peer_id = $1`, peerID))
	if errors.Is(err, pgx.ErrNoRows) {
		return k, ErrNotFound
	}
	return k, err
}

func (p *Postgres) DeleteHWKey(ctx context.Context, peerID int64) error {
	tag, err := p.pool.Exec(ctx, `DELETE FROM ento_hwkeys WHERE peer_id = $1`, peerID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (p *Postgres) HWKeys(ctx context.Context) ([]HWKey, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+hwKeyColumns+` FROM ento_hwkeys ORDER BY peer_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HWKey
	for rows.Next() {
		k, err := scanHWKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (p *Postgres) RotatePeerKey(ctx context.Context, peerID int64, oldKey, newKey wgtypes.Key) error {
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		var inUse bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ento_peers WHERE public_key = $1)
			OR EXISTS (SELECT 1 FROM ento_control_nodes WHERE public_key = $1)
			OR EXISTS (SELECT 1 FROM ento_tokens WHERE public_key = $1)`, newKey.String()).Scan(&inUse); err != nil {
			return false, err
		}
		if inUse {
			return false, ErrExists
		}
		tag, err := tx.Exec(ctx, `UPDATE ento_peers SET public_key = $3 WHERE id = $1 AND public_key = $2`,
			peerID, oldKey.String(), newKey.String())
		if isUniqueViolation(err) {
			return false, ErrExists
		}
		if err != nil {
			return false, err
		}
		if tag.RowsAffected() == 0 {
			return false, ErrNotFound
		}
		_, err = tx.Exec(ctx, `UPDATE ento_hwkeys SET rotate = false, rotated_at = now() WHERE peer_id = $1`, peerID)
		return err == nil, err
	})
}

func (p *Postgres) DeleteCheckIn(ctx context.Context, peerID int64) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM ento_checkins WHERE peer_id = $1`, peerID)
	return err
}

func (p *Postgres) CheckIns(ctx context.Context) ([]CheckIn, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+checkInColumns+` FROM ento_checkins ORDER BY peer_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckIn
	for rows.Next() {
		c, err := scanCheckIn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (p *Postgres) Routes(ctx context.Context) ([]Route, error) {
	rows, err := p.pool.Query(ctx, `SELECT name, networks, via, exit, use_by_default, created_at, created_by FROM ento_routes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Route
	for rows.Next() {
		var r Route
		var nets []string
		if err := rows.Scan(&r.Name, &nets, &r.Via, &r.Exit, &r.Default, &r.CreatedAt, &r.CreatedBy); err != nil {
			return nil, err
		}
		for _, n := range nets {
			if pr, err := netip.ParsePrefix(n); err == nil {
				r.Networks = append(r.Networks, pr)
			}
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) AddRoute(ctx context.Context, r Route) error {
	nets := make([]string, 0, len(r.Networks))
	for _, n := range r.Networks {
		nets = append(nets, n.String())
	}
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `INSERT INTO ento_routes (name, networks, via, exit, use_by_default, created_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (name) DO NOTHING`, r.Name, nets, r.Via, r.Exit, r.Default, r.CreatedAt, r.CreatedBy)
		if err == nil && tag.RowsAffected() == 0 {
			return false, ErrExists
		}
		return err == nil, err
	})
}

func (p *Postgres) DeleteRoute(ctx context.Context, name string) error {
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `DELETE FROM ento_routes WHERE name = $1`, name)
		if err == nil && tag.RowsAffected() == 0 {
			return false, ErrNotFound
		}
		return err == nil, err
	})
}

func (p *Postgres) DNSRecords(ctx context.Context) ([]DNSRecord, error) {
	rows, err := p.pool.Query(ctx, `SELECT name, address, created_at, created_by FROM ento_dns_records ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSRecord
	for rows.Next() {
		var r DNSRecord
		var addr string
		if err := rows.Scan(&r.Name, &addr, &r.CreatedAt, &r.CreatedBy); err != nil {
			return nil, err
		}
		if r.Address, err = netip.ParseAddr(addr); err != nil {
			return nil, fmt.Errorf("DNS record %s: %w", r.Name, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *Postgres) AddDNSRecord(ctx context.Context, r DNSRecord) error {
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `INSERT INTO ento_dns_records (name, address, created_at, created_by) VALUES ($1, $2, $3, $4)
			ON CONFLICT (name) DO NOTHING`, r.Name, r.Address.String(), r.CreatedAt, r.CreatedBy)
		if err == nil && tag.RowsAffected() == 0 {
			return false, ErrExists
		}
		return err == nil, err
	})
}

func (p *Postgres) DeleteDNSRecord(ctx context.Context, name string) error {
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `DELETE FROM ento_dns_records WHERE name = $1`, name)
		if err == nil && tag.RowsAffected() == 0 {
			return false, ErrNotFound
		}
		return err == nil, err
	})
}

func (p *Postgres) DNSForwards(ctx context.Context) ([]DNSForward, error) {
	rows, err := p.pool.Query(ctx, `SELECT zone, servers, created_at, created_by FROM ento_dns_forwards ORDER BY zone`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DNSForward
	for rows.Next() {
		var f DNSForward
		var servers []string
		if err := rows.Scan(&f.Zone, &servers, &f.CreatedAt, &f.CreatedBy); err != nil {
			return nil, err
		}
		for _, s := range servers {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("DNS forward %s: %w", f.Zone, err)
			}
			f.Servers = append(f.Servers, a)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (p *Postgres) AddDNSForward(ctx context.Context, f DNSForward) error {
	servers := make([]string, 0, len(f.Servers))
	for _, s := range f.Servers {
		servers = append(servers, s.String())
	}
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `INSERT INTO ento_dns_forwards (zone, servers, created_at, created_by) VALUES ($1, $2, $3, $4)
			ON CONFLICT (zone) DO NOTHING`, f.Zone, servers, f.CreatedAt, f.CreatedBy)
		if err == nil && tag.RowsAffected() == 0 {
			return false, ErrExists
		}
		return err == nil, err
	})
}

func (p *Postgres) DeleteDNSForward(ctx context.Context, zone string) error {
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		tag, err := tx.Exec(ctx, `DELETE FROM ento_dns_forwards WHERE zone = $1`, zone)
		if err == nil && tag.RowsAffected() == 0 {
			return false, ErrNotFound
		}
		return err == nil, err
	})
}

func (p *Postgres) UpdatePolicy(ctx context.Context) (UpdatePolicy, error) {
	var u UpdatePolicy
	err := p.pool.QueryRow(ctx, `SELECT mode, approved, first_group, first_hours, set_by, set_at FROM ento_update_policy WHERE id = 1`).
		Scan(&u.Mode, &u.Approved, &u.FirstGroup, &u.FirstHours, &u.SetBy, &u.SetAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return UpdatePolicy{Mode: "auto"}, nil
	}
	return u, err
}

func (p *Postgres) SetUpdatePolicy(ctx context.Context, u UpdatePolicy) error {
	return p.write(ctx, func(tx pgx.Tx) (bool, error) {
		_, err := tx.Exec(ctx, `INSERT INTO ento_update_policy (id, mode, approved, first_group, first_hours, set_by, set_at)
			VALUES (1, $1, $2, $3, $4, $5, $6) ON CONFLICT (id) DO UPDATE SET mode = excluded.mode, approved = excluded.approved,
			first_group = excluded.first_group, first_hours = excluded.first_hours, set_by = excluded.set_by, set_at = excluded.set_at`,
			u.Mode, u.Approved, u.FirstGroup, u.FirstHours, u.SetBy, u.SetAt)
		return err == nil, err
	})
}

func (p *Postgres) ReleaseOffered(ctx context.Context, version string, at time.Time) (time.Time, error) {
	var t time.Time
	err := p.pool.QueryRow(ctx, `INSERT INTO ento_release_offers (version, offered_at) VALUES ($1, $2)
		ON CONFLICT (version) DO UPDATE SET version = excluded.version RETURNING offered_at`, version, at).Scan(&t)
	return t, err
}

func (p *Postgres) RecordPersonActivity(ctx context.Context, id int64, at time.Time, reports bool, bootID string) error {
	var activity *time.Time
	if !at.IsZero() {
		activity = &at
	}
	tag, err := p.pool.Exec(ctx, `UPDATE ento_peers SET
		person_activity_at = CASE WHEN $2::timestamptz IS NULL THEN person_activity_at
			ELSE GREATEST(COALESCE(person_activity_at, $2::timestamptz), $2::timestamptz) END,
		person_reports = person_reports OR $3, boot_id = CASE WHEN $4 = '' THEN boot_id ELSE $4 END WHERE id = $1`,
		id, activity, reports, bootID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
