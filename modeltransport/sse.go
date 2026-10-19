package modeltransport

import (
	"bufio"
	"bytes"
	"io"
)

// eventBody exposes complete SSE events only. This keeps a consumer which stops
// on the [DONE] data line from racing the final blank-line delimiter split over
// another TCP read. It buffers at most one bounded event, not the whole stream.
type eventBody struct {
	io.ReadCloser
	reader  *bufio.Reader
	pending []byte
}

func (b *eventBody) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if len(b.pending) == 0 {
		var event []byte
		lineLength := 0
		for {
			line, err := b.reader.ReadSlice('\n')
			if len(event)+len(line) > maxResponseBytes {
				return 0, io.ErrUnexpectedEOF
			}
			event = append(event, line...)
			lineLength += len(line)
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				if err == io.EOF && len(event) > 0 {
					err = io.ErrUnexpectedEOF
				}
				return 0, err
			}
			if lineLength <= 2 && (bytes.Equal(line, []byte{'\n'}) || bytes.Equal(line, []byte{'\r', '\n'})) {
				b.pending = event
				break
			}
			lineLength = 0
		}
	}
	n := copy(dst, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}
