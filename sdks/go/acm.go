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

// ApproveCertificate flips a PENDING_VALIDATION certificate to ISSUED,
// the synchronous equivalent of the user clicking the validation link
// in an ACM-sent email. EMAIL-validated certs do not auto-issue, so
// tests drive their issuance through this endpoint. arnOrID accepts
// either the full certificate ARN or just the trailing UUID.
func (c *ACMClient) ApproveCertificate(ctx context.Context, arnOrID string) error {
	id := arnOrID
	if idx := strings.LastIndex(arnOrID, "certificate/"); idx >= 0 {
		id = arnOrID[idx+len("certificate/"):]
	}
	path := fmt.Sprintf("/_fakecloud/acm/certificates/%s/approve", id)
	return c.fc.doPost(ctx, path, nil, nil)
}

// CertificateChainInfo is the shape returned by GetCertificateChainInfo.
//
// fakecloud is not a PKI: ExternalCaValidated is always false,
// documenting that imported chains are stored verbatim rather than
// verified against a real trust store. The byte/block counts let
// callers confirm the PEM they uploaded round-trips intact.
type CertificateChainInfo struct {
	CertificateArn       string `json:"certificate_arn"`
	CertificatePemBytes  int    `json:"certificate_pem_bytes"`
	CertificatePemBlocks int    `json:"certificate_pem_blocks"`
	ChainPemBytes        int    `json:"chain_pem_bytes"`
	ChainPemBlocks       int    `json:"chain_pem_blocks"`
	ExternalCaValidated  bool   `json:"external_ca_validated"`
	Status               string `json:"status"`
	CertType             string `json:"cert_type"`
}

// GetCertificateChainInfo inspects a stored certificate's PEM block
// counts and byte sizes. arnOrID accepts either the full ACM ARN or
// just the trailing UUID. Use this to confirm uploaded chains
// round-trip intact, especially for ImportCertificate flows.
func (c *ACMClient) GetCertificateChainInfo(
	ctx context.Context,
	arnOrID string,
) (*CertificateChainInfo, error) {
	id := arnOrID
	if idx := strings.LastIndex(arnOrID, "certificate/"); idx >= 0 {
		id = arnOrID[idx+len("certificate/"):]
	}
	path := fmt.Sprintf("/_fakecloud/acm/certificates/%s/chain-info", id)
	var out CertificateChainInfo
	if err := c.fc.doGet(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
