package sessionfixture

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

var intentName = regexp.MustCompile(`^release-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// This resolves only a durable Create label. It does not clear bridge intent,
// resume a session, or authorize any mutation after an ambiguous RPC.
func resolveIntent(ctx context.Context, path, name string, out io.Writer) error {
	if !intentName.MatchString(name) {
		return errors.New("intent must be a recorded release-UUID name")
	}
	db, err := readOnlyDB(path)
	if err != nil {
		return err
	}
	defer db.Close()
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	rows, err := db.QueryContext(bounded, `SELECT session FROM sessions WHERE name=? LIMIT 2`, name)
	if err != nil {
		return err
	}
	defer rows.Close()
	matches := []string{}
	for rows.Next() {
		var uid string
		if err = rows.Scan(&uid); err != nil {
			return err
		}
		if !identity(uid, 256) {
			return errors.New("invalid resolved session UID")
		}
		matches = append(matches, uid)
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(matches) == 0 {
		return errors.New("unresolved intent: no session has that recorded name")
	}
	if len(matches) != 1 {
		return errors.New("ambiguous intent: multiple sessions have that recorded name")
	}
	return json.NewEncoder(out).Encode(map[string]string{"session_uid": matches[0], "intent": name})
}
