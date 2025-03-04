// MIT License
//
// Copyright (c) 2024 CrowdStrike
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package falcon

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"log/slog"
)

// FalconAPIRateLimitDecorator is an http.RoundTripper that enforces rate limits for Falcon API requests.
type FalconAPIRateLimitDecorator struct {
	transport  http.RoundTripper
	remaining  int
	maxRetries int
	retryAfter time.Time
}

// NewFalconAPIRateLimitDecorator creates a new FalconAPIRateLimitDecorator.
func NewFalconAPIRateLimitDecorator(transport http.RoundTripper) *FalconAPIRateLimitDecorator {
	return &FalconAPIRateLimitDecorator{
		transport:  transport,
		remaining:  -1,
		maxRetries: 10,
		retryAfter: time.Time{},
	}
}

// RoundTrip executes a single HTTP transaction, returning a Response for the provided Request.
func (d *FalconAPIRateLimitDecorator) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := 0; attempt <= d.maxRetries; attempt++ {
		// Check if we need to wait based on RetryAfter
		if !d.retryAfter.IsZero() && time.Now().Before(d.retryAfter) {
			waitDuration := time.Until(d.retryAfter)

			// Check if waiting would exceed the context deadline
			if deadline, ok := req.Context().Deadline(); ok {
				if time.Now().Add(waitDuration).After(deadline) {
					return nil, context.DeadlineExceeded
				}
				// Adjust waitDuration if it exceeds the deadline
				if remainingTime := time.Until(deadline); remainingTime < waitDuration {
					waitDuration = remainingTime
				}
			}

			// Use a separate goroutine for sleeping to allow for context cancellation
			sleepDone := make(chan struct{})
			go func() {
				time.Sleep(waitDuration)
				close(sleepDone)
			}()

			// Wait for either sleep to finish or context to be cancelled
			select {
			case <-sleepDone:
				// Sleep completed
			case <-req.Context().Done():
				return nil, req.Context().Err()
			}

			d.retryAfter = time.Time{} // Reset RetryAfter
		}

		d.remaining--

		// Perform the actual request with a context-aware transport
		resp, err = d.transport.RoundTrip(req)
		if err != nil {
			// Check if the error is due to context deadline
			if err == context.DeadlineExceeded || err == context.Canceled {
				return nil, err
			}
			// For other errors, retry
			continue
		}

		// Handle 429 Too Many Requests
		if resp.StatusCode == 429 {

			// Update RetryAfter based on response headers
			if retryAfter := resp.Header.Get("X-RateLimit-RetryAfter"); retryAfter != "" {
				if retrySeconds, err := strconv.ParseInt(retryAfter, 10, 64); err == nil {
					retryTime := time.Unix(retrySeconds, 0)
					waitDuration := time.Duration(math.Max(float64(time.Until(retryTime)), 10*float64(time.Second)))
					d.retryAfter = time.Now().Add(waitDuration)
				}
			}

			slog.Info(fmt.Sprintf("Rate limit exceeded. Retrying after %s", time.Until(d.retryAfter)))
			continue
		}

		// If we get here, the request was successful
		break
	}

	if resp == nil {
		return nil, fmt.Errorf("max retries exceeded")
	}

	return resp, nil
}
