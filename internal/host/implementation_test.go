package host

import (
	"context"
	"log/slog"
	"testing"
)

func TestApplicationRejectsInvalidConfig(t *testing.T) {
	app, err := newApplication(context.Background(), Config{}, nil, slog.Default())
	if app != nil {
		app.Close()
	}
	if err == nil {
		t.Fatal("invalid host configuration started")
	}
}
