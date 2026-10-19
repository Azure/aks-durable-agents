package modeltransport

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSSEEventDelimiterAfterFullBuffer(t *testing.T) {
	text := strings.Repeat("x", 4096) + "\n\n"
	b := &eventBody{ReadCloser: io.NopCloser(strings.NewReader(text)), reader: bufio.NewReader(strings.NewReader(text))}
	dst := make([]byte, 8192)
	n, err := b.Read(dst)
	if err != nil || string(dst[:n]) != text {
		t.Fatalf("complete event missing delimiter: n=%d err=%v", n, err)
	}
}

func TestSSEDoneDoesNotWaitForNetworkEOF(t *testing.T) {
	p, _, _ := openTestPolicy(t)
	release := make(chan struct{})
	defer close(release)
	c, target := boundedFixture(t, p, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, "data: "+usageResponse+"\n\ndata: [DONE]\n\n")
		w.(http.Flusher).Flush()
		<-release
	}, goodCredential())
	c.Timeout = 200 * time.Millisecond
	if err := boundedSend(c, target, chat("x", true)); err != nil {
		t.Fatalf("complete SSE incorrectly waits for EOF: %v", err)
	}
}
