package oidc_test

import (
	"net/url"
	"testing"

	oauthelia2 "authelia.com/provider/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/oidc"
)

func TestNewClaimRequests(t *testing.T) {
	form := url.Values{}

	form.Set(oidc.FormParameterClaims, `{"id_token":{"sub":{"value":"aaaa"}}}`)

	requests, err := oidc.NewClaimRequests(form)
	require.NoError(t, err)

	assert.NotNil(t, requests)

	var (
		requested string
		ok        bool
	)

	requested, ok = requests.MatchesSubject("aaaa")
	assert.Equal(t, "aaaa", requested)
	assert.True(t, ok)

	requested, ok = requests.MatchesSubject("aaaaa")
	assert.Equal(t, "aaaa", requested)
	assert.False(t, ok)
}

func TestGrantClaimsUserInfo(t *testing.T) {
	strategy := oauthelia2.ExactScopeStrategy

	testCases := []struct {
		name     string
		client   oidc.Client
		scopes   oauthelia2.Arguments
		requests map[string]*oidc.ClaimRequest
		detailer oidc.UserDetailer
		claims   map[string]any
		expected map[string]any
	}{
		{
			"ShouldGrantUserInfoClaims",
			&oidc.RegisteredClient{},
			[]string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeGroups, oidc.ScopeEmail},
			nil,
			&testDetailer{
				username: "john",
				groups:   []string{"abc", "123"},
				name:     "John Smith",
				emails:   []string{"john.smith@authelia.com"},
			},
			map[string]any{"auth_time": 123},
			map[string]any{"auth_time": 123, "email": "john.smith@authelia.com", "email_verified": true, "groups": []string{"abc", "123"}, "name": "John Smith", "preferred_username": "john"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			extra := map[string]any{}

			oidc.GrantClaimRequests(strategy, tc.client, tc.requests, tc.detailer, extra)
			oidc.GrantScopedClaims(strategy, tc.client, tc.scopes, tc.detailer, tc.claims, extra)

			assert.EqualValues(t, tc.expected, extra)
		})
	}
}

type testDetailer struct {
	username  string
	groups    []string
	name      string
	emails    []string
	given     string
	family    string
	middle    string
	nickname  string
	profile   string
	picture   string
	website   string
	gender    string
	birthdate string
	info      string
	locale    string
	number    string
	extension string
	address   string
	locality  string
	region    string
	postcode  string
	country   string
}

func (t testDetailer) GetGivenName() (given string) {
	return t.given
}

func (t testDetailer) GetFamilyName() (family string) {
	return t.family
}

func (t testDetailer) GetMiddleName() (middle string) {
	return t.middle
}

func (t testDetailer) GetNickname() (nickname string) {
	return t.nickname
}

func (t testDetailer) GetProfile() (profile string) {
	return t.profile
}

func (t testDetailer) GetPicture() (picture string) {
	return t.picture
}

func (t testDetailer) GetWebsite() (website string) {
	return t.website
}

func (t testDetailer) GetGender() (gender string) {
	return t.gender
}

func (t testDetailer) GetBirthdate() (birthdate string) {
	return t.birthdate
}

func (t testDetailer) GetZoneInfo() (info string) {
	return t.info
}

func (t testDetailer) GetLocale() (locale string) {
	return t.locale
}

func (t testDetailer) GetPhoneNumber() (number string) {
	return t.number
}

func (t testDetailer) GetPhoneExtension() (extension string) {
	return t.extension
}

func (t testDetailer) GetOpenIDConnectPhoneNumber() (number string) {
	return t.number
}

func (t testDetailer) GetStreetAddress() (address string) {
	return t.address
}

func (t testDetailer) GetLocality() (locality string) {
	return t.locality
}

func (t testDetailer) GetRegion() (region string) {
	return t.region
}

func (t testDetailer) GetPostalCode() (postcode string) {
	return t.postcode
}

func (t testDetailer) GetCountry() (country string) {
	return t.country
}

func (t testDetailer) GetUsername() (username string) {
	return t.username
}

func (t testDetailer) GetGroups() (groups []string) {
	return t.groups
}

func (t testDetailer) GetDisplayName() (name string) {
	return t.name
}

func (t testDetailer) GetEmails() (emails []string) {
	return t.emails
}

var (
	_ oidc.UserDetailer = (*testDetailer)(nil)
)
