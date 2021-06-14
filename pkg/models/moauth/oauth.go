package moauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync"

	"github.com/wonksing/oauth-server/pkg/models/merror"
)

const (
	KeyReturnURI   = "oauth_return_uri"
	KeyAccessToken = "oauth_access_token"
	KeyRedirectURI = "oauth_redirect_uri"
)

type OAuthUserID struct {
}
type OAuthAllowStatus struct {
}

func GetUserIDContext(ctx context.Context) (string, error) {
	tmp := ctx.Value(OAuthUserID{})
	if tmp == nil {
		return "", merror.ErrorUserIDNotFound
	}

	userID := strings.TrimSpace(tmp.(string))
	if userID == "" {
		return "", merror.ErrorUserIDNotFound
	}

	return userID, nil
}

func WithUserIDContext(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, OAuthUserID{}, userID)
}

func GetAllowStatusContext(ctx context.Context) (string, error) {
	tmp := ctx.Value(OAuthAllowStatus{})
	if tmp == nil || tmp.(string) == "" {
		return "", merror.ErrorUserNeedToAllow
	}
	if tmp != "yes" {
		return "", merror.ErrorUserDidNotAllow
	}
	return tmp.(string), nil
}

func WithAllowStatusContext(ctx context.Context, status string) context.Context {
	return context.WithValue(ctx, OAuthAllowStatus{}, status)
}

type OAuthScope struct {
	sync.RWMutex
	data map[string]AuthorizedResources
}

func NewOAuthScope() *OAuthScope {
	return &OAuthScope{
		data: make(map[string]AuthorizedResources),
	}
}

func (s *OAuthScope) Get(scope string) (AuthorizedResources, error) {
	s.RLock()
	defer s.RUnlock()

	if ar, ok := s.data[scope]; ok {
		return ar, nil
	}
	return nil, errors.New("scope not found")
}

func (s *OAuthScope) Set(scope string, ar AuthorizedResources) error {
	s.Lock()
	defer s.Unlock()
	s.data[scope] = ar
	return nil
}

func (s *OAuthScope) PickAllowedScope(clientScope string) string {
	s.RLock()
	defer s.RUnlock()

	allowedScope := ""
	clientScopeList := strings.Split(clientScope, " ")
	for _, scope := range clientScopeList {
		if _, ok := s.data[scope]; ok {
			allowedScope += scope + " "
		}
	}

	return strings.TrimSpace(allowedScope)
}

func (s *OAuthScope) FilterScope(allowed, requested string) (string, error) {
	if allowed == "" {
		return "", merror.ErrorNoAllowedScope
	}
	allowedScopeList := strings.Split(allowed, " ")

	if requested == "" {
		requested = allowed
	}
	requestedScopeList := strings.Split(requested, " ")
	matchedScope := ""
	for _, rs := range requestedScopeList {
		for _, as := range allowedScopeList {
			if rs == as {
				matchedScope += rs + " "
				break
			}
		}
	}
	matchedScope = strings.TrimSpace(matchedScope)
	return matchedScope, nil
}

type AuthorizedResource struct {
	Path   string
	Get    bool
	Post   bool
	Put    bool
	Delete bool
}
type AuthorizedResources []AuthorizedResource

type OAuthClient struct {
	ID     string
	Secret string
	Domain string
	UserID string
	Scope  string
}
type OAuthClientList []*OAuthClient

func (c *OAuthClient) GetID() string {
	return c.ID
}

// GetSecret client secret
func (c *OAuthClient) GetSecret() string {
	return c.Secret
}

// GetDomain client domain
func (c *OAuthClient) GetDomain() string {
	return c.Domain
}

// GetUserID user id
func (c *OAuthClient) GetUserID() string {
	return c.UserID
}

func (c *OAuthClient) GetScope() string {
	return c.Scope
}

func GenCodeChallengeS256(s string) string {
	s256 := sha256.Sum256([]byte(s))
	return base64.URLEncoding.EncodeToString(s256[:])
}
