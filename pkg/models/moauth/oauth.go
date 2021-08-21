package moauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
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

func NewOAuthScopeMap(m map[string]interface{}) *OAuthScope {
	scopeMap := NewOAuthScope()
	for k, v := range m {

		list := make(AuthorizedResources, 0)
		resources := strings.Split(v.(string), ",")
		for _, r := range resources {
			ar := AuthorizedResource{}
			ar.Path = r
			tmp := strings.Split(k, ":")
			if len(tmp) == 1 {
				ar.Get = true
				ar.Post = true
				ar.Put = true
				ar.Delete = true
			} else {
				switch tmp[len(tmp)-1] {
				case "read":
					ar.Get = true
				case "update":
					ar.Post = true
				case "write":
					ar.Put = true
				case "delete":
					ar.Delete = true
				}
			}
			list = append(list, ar)
		}
		scopeMap.Set(k, list)
	}
	return scopeMap
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

func (s *OAuthScope) CheckAuthorizedResource(scope, path, method string) bool {
	ars, err := s.Get(scope)
	if err != nil {
		return false
	}

	return ars.CheckAuthorizedResource(path, method)
}

type AuthorizedResource struct {
	Path   string
	Get    bool
	Post   bool
	Put    bool
	Delete bool
}

func (a *AuthorizedResource) CheckAuthorizedResource(path string, method string) bool {
	if a.Path != path {
		return false
	}

	if a.Get && method == http.MethodGet {
		return true
	}
	if a.Post && method == http.MethodPost {
		return true
	}
	if a.Put && method == http.MethodPut {
		return true
	}
	if a.Delete && method == http.MethodDelete {
		return true
	}

	return false
}

type AuthorizedResources []AuthorizedResource

func (ar *AuthorizedResources) CheckAuthorizedResource(path, method string) bool {
	for _, s := range *ar {
		if s.CheckAuthorizedResource(path, method) {
			return true
		}
	}
	return false
}

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
