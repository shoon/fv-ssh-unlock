// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestFailureErrorUnwrapAndClassification(t *testing.T) {
	var nilFailure *Failure
	if got := nilFailure.Error(); got != "monitor operation failed" {
		t.Fatalf("nil Failure.Error() = %q", got)
	}
	if nilFailure.Unwrap() != nil {
		t.Fatal("nil Failure.Unwrap() returned an error")
	}

	withoutCause := &Failure{Kind: FailureHostKey}
	if got := withoutCause.Error(); !strings.Contains(got, string(FailureHostKey)) {
		t.Fatalf("Failure.Error() = %q", got)
	}
	cause := errors.New("credential rejected")
	failure := NewFailure(FailureCredential, cause)
	if !errors.Is(failure, cause) || FailureKindOf(failure) != FailureCredential {
		t.Fatalf("classified failure did not preserve its cause: %v", failure)
	}
	if FailureKindOf(context.DeadlineExceeded) != FailureUnreachable {
		t.Fatal("deadline was not classified as unreachable")
	}
	if FailureKindOf(errors.New("plain failure")) != FailureTransient {
		t.Fatal("unclassified failure was not transient")
	}
	generated := NewFailure(FailureTransient, nil)
	if generated == nil || !strings.Contains(generated.Error(), "operation failed") {
		t.Fatalf("nil cause was not replaced: %v", generated)
	}
}
