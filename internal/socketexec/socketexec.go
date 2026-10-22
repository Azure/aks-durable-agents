// Package socketexec adapts the public v1 Unix tool executor protocol.
package socketexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/agent-primitives/sessions/controller"
)

const maxBytes = 1 << 20

var errInvalidJSON = errors.New("invalid JSON object")

type executorConfig struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Socket    string `json:"socket"`
	TimeoutMS *int   `json:"timeout_ms"`
}

type routeConfig struct {
	Harness      string `json:"harness"`
	Tool         string `json:"tool"`
	Executor     string `json:"executor"`
	DurableDedup *bool  `json:"durable_dedup"`
}

type binding struct {
	executor executorConfig
	dedup    bool
}

// Binding keeps an executor and its exact durable-dedup declarations together.
// The executor, not this declaration, must durably deduplicate session/key retries.
type Binding struct {
	Execute      controller.ToolFunc
	DurableDedup func(tool string) bool
}

// Load returns only the dispatchers from LoadBindings for executor-only callers.
func Load(path string, harnesses map[string]string) (map[string]controller.ToolFunc, error) {
	bindings, err := LoadBindings(path, harnesses)
	if err != nil {
		return nil, err
	}
	result := make(map[string]controller.ToolFunc, len(bindings))
	for name, binding := range bindings {
		result[name] = binding.Execute
	}
	return result, nil
}

// LoadBindings reads v1 tools.json and returns exact, per-harness dispatchers and
// dedup declarations. It validates the entire configuration without connecting to
// sockets. Only static harness names are eligible; endpoint values are unused.
func LoadBindings(path string, harnesses map[string]string) (map[string]Binding, error) {
	result := make(map[string]Binding)
	if path == "" {
		return result, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("socketexec: cannot open configuration")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return nil, errors.New("socketexec: cannot read bounded configuration")
	}
	var config struct {
		Version   int               `json:"version"`
		Executors []json.RawMessage `json:"executors"`
		Tools     []json.RawMessage `json:"tools"`
	}
	if object(data, &config, "version executors tools", "") != nil || config.Version != 1 {
		return nil, errors.New("socketexec: invalid v1 configuration")
	}
	executors := make(map[string]executorConfig)
	for _, raw := range config.Executors {
		var ex executorConfig
		if object(raw, &ex, "name type socket timeout_ms", "") != nil || ex.Name == "" || ex.Type != "unix" || !filepath.IsAbs(ex.Socket) || strings.ContainsRune(ex.Socket, 0) || len(ex.Socket) > 103 {
			return nil, errors.New("socketexec: invalid executor configuration")
		}
		if _, exists := executors[ex.Name]; exists {
			return nil, errors.New("socketexec: duplicate executor name")
		}
		if ex.TimeoutMS == nil {
			ms := 30000
			ex.TimeoutMS = &ms
		}
		if *ex.TimeoutMS < 1 || *ex.TimeoutMS > 300000 {
			return nil, errors.New("socketexec: invalid executor timeout")
		}
		executors[ex.Name] = ex
	}
	routes := make(map[string]map[string]binding)
	var declarations []routeConfig
	for _, raw := range config.Tools {
		var route routeConfig
		if object(raw, &route, "harness tool executor durable_dedup", "durable_dedup") != nil || route.Harness == "" || route.Tool == "" || route.Executor == "" || strings.ContainsAny(route.Harness+route.Tool, "*") {
			return nil, errors.New("socketexec: invalid tool route")
		}
		ex, exists := executors[route.Executor]
		if !exists {
			return nil, errors.New("socketexec: unknown route executor")
		}
		if _, exists := harnesses[route.Harness]; !exists {
			return nil, errors.New("socketexec: route harness is not statically configured")
		}
		if routes[route.Harness] == nil {
			routes[route.Harness] = make(map[string]binding)
		}
		if _, exists := routes[route.Harness][route.Tool]; exists {
			return nil, errors.New("socketexec: duplicate tool route")
		}
		routes[route.Harness][route.Tool] = binding{executor: ex, dedup: route.DurableDedup != nil && *route.DurableDedup}
		declarations = append(declarations, route)
	}
	for harness, tools := range routes {
		result[harness] = Binding{
			Execute: toolFunc(harness, tools),
			DurableDedup: func(tool string) bool {
				return tools[tool].dedup
			},
		}
	}
	for _, route := range declarations {
		var dedup any = "unknown"
		if route.DurableDedup != nil {
			dedup = *route.DurableDedup
		}
		level := slog.LevelWarn
		if route.DurableDedup != nil && *route.DurableDedup {
			level = slog.LevelInfo
		}
		slog.Log(context.Background(), level, "configured tool executor", "harness", route.Harness, "tool", route.Tool, "executor", route.Executor, "durable_dedup", dedup)
	}
	return result, nil
}

func stageError(harness, tool, stage string, cause error) error {
	// Only context sentinels are safe to wrap; OS and JSON errors can embed payloads.
	if cause != nil {
		return fmt.Errorf("socketexec: harness %q tool %q: %s: %w", harness, tool, stage, cause)
	}
	return fmt.Errorf("socketexec: harness %q tool %q: %s", harness, tool, stage)
}

func callError(ctx context.Context, harness, tool, stage string) error {
	cause := ctx.Err()
	// A socket deadline can fire just before the context's timer callback.
	if deadline, ok := ctx.Deadline(); cause == nil && ok && !time.Now().Before(deadline) {
		cause = context.DeadlineExceeded
	}
	return stageError(harness, tool, stage, cause)
}

func timeout(ex executorConfig) time.Duration {
	return time.Duration(*ex.TimeoutMS) * time.Millisecond
}
