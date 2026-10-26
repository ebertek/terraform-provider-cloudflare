package zero_trust_access_policy

import (
	"context"
	"testing"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/customfield"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestPruneEmptyIncludeSelectors(t *testing.T) {
	ctx := context.Background()

	input := []ZeroTrustAccessPolicyIncludeModel{
		{
			IP: &ZeroTrustAccessPolicyIncludeIPModel{
				IP: types.StringValue("192.0.2.10/32"),
			},
			DevicePosture: &ZeroTrustAccessPolicyIncludeDevicePostureModel{
				IntegrationUID: types.StringNull(),
			},
		},
		{
			Email: &ZeroTrustAccessPolicyIncludeEmailModel{
				Email: types.StringValue("test@example.com"),
			},
			OIDC: &ZeroTrustAccessPolicyIncludeOIDCModel{
				ClaimName:          types.StringNull(),
				ClaimValue:         types.StringNull(),
				IdentityProviderID: types.StringNull(),
			},
		},
		{
			DevicePosture: &ZeroTrustAccessPolicyIncludeDevicePostureModel{
				IntegrationUID: types.StringValue("valid-posture-id"),
			},
		},
		{
			OIDC: &ZeroTrustAccessPolicyIncludeOIDCModel{
				ClaimName:          types.StringValue("groups"),
				ClaimValue:         types.StringValue("admins"),
				IdentityProviderID: types.StringValue("valid-idp-id"),
			},
		},
	}

	set, diags := customfield.NewObjectSet(ctx, input)
	if diags.HasError() {
		t.Fatalf("create input set: %v", diags)
	}

	diags = pruneEmptyIncludeSelectors(ctx, &set)
	if diags.HasError() {
		t.Fatalf("normalize selectors: %v", diags)
	}

	result, diags := set.AsStructSliceT(ctx)
	if diags.HasError() {
		t.Fatalf("read normalized set: %v", diags)
	}
	if len(result) != 4 {
		t.Fatalf("expected four preserved selectors, got %d", len(result))
	}

	var foundIP, foundEmail, foundPosture, foundOIDC bool

	for _, condition := range result {
		switch {
		case condition.IP != nil &&
			condition.IP.IP.ValueString() == "192.0.2.10/32":
			foundIP = true
			if condition.DevicePosture != nil {
				t.Error("phantom device_posture was not removed")
			}

		case condition.Email != nil &&
			condition.Email.Email.ValueString() == "test@example.com":
			foundEmail = true
			if condition.OIDC != nil {
				t.Error("phantom OIDC was not removed")
			}

		case condition.DevicePosture != nil &&
			condition.DevicePosture.IntegrationUID.ValueString() == "valid-posture-id":
			foundPosture = true

		case condition.OIDC != nil &&
			condition.OIDC.ClaimName.ValueString() == "groups":
			foundOIDC = true
		}
	}

	if !foundIP || !foundEmail || !foundPosture || !foundOIDC {
		t.Errorf(
			"missing legitimate selectors: ip=%t email=%t posture=%t oidc=%t",
			foundIP, foundEmail, foundPosture, foundOIDC,
		)
	}
}
