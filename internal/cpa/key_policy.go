package cpa

import (
	"context"
	"cpa-usage-keeper/internal/cpa/dto/cpaapikeys"
	"fmt"
	"net/http"
)

// Policy IDs are usage group references, never API credentials.
func (c *Client) FetchKeyPolicyKeys(ctx context.Context) ([]cpaapikeys.PolicyKey, error) {
	var payload struct {
		Keys []cpaapikeys.PolicyKey `json:"keys"`
	}
	status, _, err := c.doManagementJSONRequest(ctx, "/v0/management/plugins/cpa-key-policy/keys?limit=1000", &payload, "key policy identities")
	if status == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if payload.Keys == nil || len(payload.Keys) >= 1000 {
		return nil, fmt.Errorf("incomplete key policy identity snapshot")
	}
	return payload.Keys, nil
}
