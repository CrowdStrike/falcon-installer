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
	"net/http"
	"strconv"
	"testing"
	"time"
)

// MockTransport implements http.RoundTripper for testing.
type MockTransport struct {
	responses        []*http.Response
	errors           []error
	requestCount     int
	requestsReceived []*http.Request
}

func (m *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if m.requestCount >= len(m.responses) {
		return nil, fmt.Errorf("no more mock responses")
	}

	m.requestsReceived = append(m.requestsReceived, req.Clone(req.Context()))
	resp := m.responses[m.requestCount]
	err := m.errors[m.requestCount]
	m.requestCount++
	return resp, err
}

func TestNewFalconAPIRateLimitDecorator(t *testing.T) {
	mockTransport := &MockTransport{}
	decorator := NewFalconAPIRateLimitDecorator(mockTransport)

	if decorator.transport != mockTransport {
		t.Errorf("Expected transport to be %v, got %v", mockTransport, decorator.transport)
	}

	if decorator.maxRetries != 10 {
		t.Errorf("Expected maxRetries to be 10, got %d", decorator.maxRetries)
	}

	if decorator.remaining != -1 {
		t.Errorf("Expected remaining to be -1, got %d", decorator.remaining)
	}

	if !decorator.retryAfter.IsZero() {
		t.Errorf("Expected retryAfter to be zero time, got %v", decorator.retryAfter)
	}
}

func TestRoundTripSuccess(t *testing.T) {
	// Create a successful response
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	mockTransport := &MockTransport{
		responses: []*http.Response{resp},
		errors:    []error{nil},
	}

	decorator := NewFalconAPIRateLimitDecorator(mockTransport)
	req, _ := http.NewRequest("GET", "https://example.com", nil)

	result, err := decorator.RoundTrip(req)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if result != resp {
		t.Errorf("Expected response %v, got %v", resp, result)
	}

	if mockTransport.requestCount != 1 {
		t.Errorf("Expected 1 request, got %d", mockTransport.requestCount)
	}
}

func TestRoundTripRateLimitRetry(t *testing.T) {
	// Create a rate limit response followed by a success
	retryAfter := time.Now().Add(2 * time.Second).Unix()

	rateLimitResp := &http.Response{
		StatusCode: 429,
		Header:     make(http.Header),
	}
	rateLimitResp.Header.Set("X-RateLimit-RetryAfter", strconv.FormatInt(retryAfter, 10))

	successResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	mockTransport := &MockTransport{
		responses: []*http.Response{rateLimitResp, successResp},
		errors:    []error{nil, nil},
	}

	decorator := NewFalconAPIRateLimitDecorator(mockTransport)
	// Use a shorter retry time for testing
	decorator.maxRetries = 1

	req, _ := http.NewRequest("GET", "https://example.com", nil)

	// Use a context with a timeout longer than our retry delay
	req = req.WithContext(context.Background())

	start := time.Now()
	result, err := decorator.RoundTrip(req)
	elapsed := time.Since(start)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if result != successResp {
		t.Errorf("Expected response %v, got %v", successResp, result)
	}

	if mockTransport.requestCount != 2 {
		t.Errorf("Expected 2 requests, got %d", mockTransport.requestCount)
	}

	// Should have waited at least a little bit
	if elapsed < 10*time.Millisecond {
		t.Errorf("Expected delay for rate limiting, but request completed too quickly: %v", elapsed)
	}
}

func TestRoundTripContextDeadlineExceeded(t *testing.T) {
	// Create a rate limit response
	retryAfter := time.Now().Add(10 * time.Second).Unix()

	rateLimitResp := &http.Response{
		StatusCode: 429,
		Header:     make(http.Header),
	}
	rateLimitResp.Header.Set("X-RateLimit-RetryAfter", strconv.FormatInt(retryAfter, 10))

	mockTransport := &MockTransport{
		responses: []*http.Response{rateLimitResp},
		errors:    []error{nil},
	}

	decorator := NewFalconAPIRateLimitDecorator(mockTransport)

	req, _ := http.NewRequest("GET", "https://example.com", nil)

	// Use a context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	_, err := decorator.RoundTrip(req)

	if err != context.DeadlineExceeded {
		t.Errorf("Expected DeadlineExceeded error, got %v", err)
	}
}

func TestRoundTripContextCancellation(t *testing.T) {
	// Create a rate limit response
	retryAfter := time.Now().Add(5 * time.Second).Unix()

	rateLimitResp := &http.Response{
		StatusCode: 429,
		Header:     make(http.Header),
	}
	rateLimitResp.Header.Set("X-RateLimit-RetryAfter", strconv.FormatInt(retryAfter, 10))

	mockTransport := &MockTransport{
		responses: []*http.Response{rateLimitResp},
		errors:    []error{nil},
	}

	decorator := NewFalconAPIRateLimitDecorator(mockTransport)

	req, _ := http.NewRequest("GET", "https://example.com", nil)

	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)

	// Cancel the context after a short delay
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	_, err := decorator.RoundTrip(req)

	if err != context.Canceled {
		t.Errorf("Expected Canceled error, got %v", err)
	}
}

func TestRoundTripMaxRetriesExceeded(t *testing.T) {
	// Create a transport that returns 429s followed by an error that sets resp to nil
	mockTransport := &MockTransport{}

	// Add maxRetries responses that are all 429s
	for i := 0; i < 2; i++ { // 2 is maxRetries
		resp := &http.Response{
			StatusCode: 429,
			Header:     make(http.Header),
		}
		resp.Header.Set("X-RateLimit-RetryAfter",
			strconv.FormatInt(time.Now().Add(1*time.Millisecond).Unix(), 10))

		mockTransport.responses = append(mockTransport.responses, resp)
		mockTransport.errors = append(mockTransport.errors, nil)
	}

	// Add a final response that will set resp to nil
	mockTransport.responses = append(mockTransport.responses, nil)
	mockTransport.errors = append(mockTransport.errors, fmt.Errorf("network error"))

	decorator := NewFalconAPIRateLimitDecorator(mockTransport)
	decorator.maxRetries = 2 // Set to a small number for testing

	req, _ := http.NewRequest("GET", "https://example.com", nil)

	req = req.WithContext(context.Background())

	_, err := decorator.RoundTrip(req)

	if err == nil || err.Error() != "max retries exceeded" {
		t.Errorf("Expected 'max retries exceeded' error, got %v", err)
	}

	// We expect initial + maxRetries attempts = 3 total requests
	expectedRequests := 1 + decorator.maxRetries
	if mockTransport.requestCount != expectedRequests {
		t.Errorf("Expected %d requests, got %d", expectedRequests, mockTransport.requestCount)
	}
}

func TestRoundTripTransportError(t *testing.T) {
	expectedErr := fmt.Errorf("network error")

	mockTransport := &MockTransport{
		responses: []*http.Response{nil, nil, {StatusCode: 200}},
		errors:    []error{expectedErr, expectedErr, nil},
	}

	decorator := NewFalconAPIRateLimitDecorator(mockTransport)
	decorator.maxRetries = 2

	req, _ := http.NewRequest("GET", "https://example.com", nil)

	result, err := decorator.RoundTrip(req)

	if err != nil {
		t.Errorf("Expected no error after successful retry, got %v", err)
	}

	if result == nil || result.StatusCode != 200 {
		t.Errorf("Expected successful response after retries")
	}

	if mockTransport.requestCount != 3 {
		t.Errorf("Expected 3 requests, got %d", mockTransport.requestCount)
	}
}

func TestRoundTripInvalidRetryAfterHeader(t *testing.T) {
	// Create a rate limit response with invalid RetryAfter header
	rateLimitResp := &http.Response{
		StatusCode: 429,
		Header:     make(http.Header),
	}
	rateLimitResp.Header.Set("X-RateLimit-RetryAfter", "not-a-number")

	successResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	mockTransport := &MockTransport{
		responses: []*http.Response{rateLimitResp, successResp},
		errors:    []error{nil, nil},
	}

	decorator := NewFalconAPIRateLimitDecorator(mockTransport)

	req, _ := http.NewRequest("GET", "https://example.com", nil)

	result, err := decorator.RoundTrip(req)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if result != successResp {
		t.Errorf("Expected successful response after retry")
	}
}
