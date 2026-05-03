package fakecloud

import (
	"context"
	"fmt"
	"strings"
)

// ACMClient provides access to ACM admin endpoints.
//
// Wraps the per-certificate status admin endpoint that lets tests flip a
// stored certificate between PENDING_VALIDATION, ISSUED, FAILED, and
// VALIDATION_TIMED_OUT without waiting on the auto-issue tick, so
// validation-failure flows can be exercised end-to-end.
type ACMClient struct {
	fc *FakeCloud
}

// SetCertificateStatusRequest is the JSON body sent to the admin endpoint.
//
// Status is one of "ISSUED", "FAILED", or "VALIDATION_TIMED_OUT". Reason
// is recorded as FailureReason on DescribeCertificate for non-ISSUED
// statuses; ignored when "ISSUED".
type SetCertificateStatusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// SetCertificateStatus flips an ACM certificate's status synchronously.
// arnOrID accepts either the full certificate ARN or just the trailing
// UUID. Pass an empty Reason to omit it.
func (c *ACMClient) SetCertificateStatus(
	ctx context.Context,
	arnOrID string,
	req *SetCertificateStatusRequest,
) error {
	id := arnOrID
	if idx := strings.LastIndex(arnOrID, "certificate/"); idx >= 0 {
		id = arnOrID[idx+len("certificate/"):]
	}
	path := fmt.Sprintf("/_fakecloud/acm/certificates/%s/status", id)
	return c.fc.doPost(ctx, path, req, nil)
}
