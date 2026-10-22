package qualification

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"syscall"

	sqlite3 "modernc.org/sqlite/lib"
)

// Return stable classifications only: driver/filesystem errors may contain
// private paths or SQL values. Unavailability never proves an operation aborted.
func databaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrIntegrity
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		// A hot rollback journal must stay fenced, not become an ordinary outage.
		switch coded.Code() {
		case sqlite3.SQLITE_READONLY_ROLLBACK, sqlite3.SQLITE_READONLY_DBMOVED, sqlite3.SQLITE_IOERR_DATA, sqlite3.SQLITE_IOERR_CORRUPTFS:
			return ErrIntegrity
		}
		switch coded.Code() & 0xff {
		case sqlite3.SQLITE_FULL, sqlite3.SQLITE_IOERR, sqlite3.SQLITE_CANTOPEN, sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_NOMEM, sqlite3.SQLITE_READONLY:
			return ErrUnavailable
		default:
			return ErrIntegrity
		}
	}
	return ErrUnavailable
}
func fileError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrExist) || errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.EISDIR) || errors.Is(err, syscall.ENXIO) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrIntegrity
	}
	return ErrUnavailable
}
