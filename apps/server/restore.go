package main

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

func lockStore(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, errors.New("database is locked by a running HomeProxy process")
	}
	return f, nil
}

func backupStore(source, destination string) error {
	if _, err := os.Stat(source); err != nil {
		return err
	}
	db, err := openStore(source)
	if err != nil {
		return err
	}
	defer db.Close()
	return affectedBackup(db, destination)
}

func restoreStore(cfg settings, source string) error {
	raw, err := os.ReadFile(cfg.KeyFile)
	if err != nil || len(raw) != 32 {
		return errors.New("original encryption key is required for restore")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return err
	}
	secrets, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	header := make([]byte, 16)
	if _, err := io.ReadFull(in, header); err != nil || string(header) != "SQLite format 3\x00" {
		return errors.New("source is not a SQLite backup")
	}
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return err
	}
	candidate, err := os.CreateTemp(filepath.Dir(cfg.Database), ".restore-*.sqlite")
	if err != nil {
		return err
	}
	path := candidate.Name()
	defer os.Remove(path)
	_, err = io.Copy(candidate, in)
	closeErr := candidate.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	in.Close()
	restored, err := openStore(path)
	if err != nil {
		return err
	}
	defer restored.Close()
	if err := validateBackup(restored, secrets); err != nil {
		return err
	}
	version, err := revision(restored)
	if err != nil {
		return err
	}
	var revoked []obj
	if _, err := os.Stat(cfg.Database); err == nil {
		old, err := openStore(cfg.Database)
		if err != nil {
			return err
		}
		defer old.Close()
		current, err := revision(old)
		if err != nil {
			return err
		}
		version = max(version, current)
		revoked, err = list(old, "SELECT id FROM devices WHERE revoked=1")
		if err != nil {
			return err
		}
		dir := filepath.Join(filepath.Dir(cfg.Database), "backups")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		previous := filepath.Join(dir, "before-restore-"+uuid()+".sqlite")
		if err := affectedBackup(old, previous); err != nil {
			return err
		}
		if err := checkpoint(old); err != nil {
			return err
		}
		if err := old.Close(); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := updateRestored(restored, version+1, revoked); err != nil {
		return err
	}
	if err := checkpoint(restored); err != nil {
		return err
	}
	if err := restored.Close(); err != nil {
		return err
	}
	return os.Rename(path, cfg.Database)
}

func updateRestored(db *sql.DB, version int64, revoked []obj) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, row := range revoked {
		if _, err := tx.Exec("UPDATE devices SET revoked=1,invite_hash=NULL,token_hash=NULL WHERE id=?", row["id"]); err != nil {
			return err
		}
	}
	if _, err := tx.Exec("UPDATE state SET revision=?", version); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE rules SET revision=?", version); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE service_groups SET revision=?", version); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO audit VALUES(?,?,?)", version, "backup.restored", time.Now().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func validateBackup(db *sql.DB, secrets cipher.AEAD) error {
	var integrity string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("SQLite backup failed integrity validation")
	}
	var broken int
	if err := db.QueryRow("SELECT count(*) FROM pragma_foreign_key_check").Scan(&broken); err != nil || broken != 0 {
		return errors.New("SQLite backup contains inconsistent references")
	}
	rows, err := db.Query("SELECT id,credentials FROM proxies")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var value []byte
		if err := rows.Scan(&id, &value); err != nil {
			return err
		}
		if _, err := secrets.Open(nil, nil, value, []byte(id)); err != nil {
			return errors.New("backup requires a different encryption key")
		}
	}
	return rows.Err()
}

func checkpoint(db *sql.DB) error {
	var busy, pages, written int
	if err := db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &pages, &written); err != nil {
		return err
	}
	if busy != 0 {
		return errors.New("SQLite checkpoint was blocked")
	}
	return nil
}
