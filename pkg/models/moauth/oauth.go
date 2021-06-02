package moauth

import (
	"context"
	"errors"
	"strings"

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
	if tmp == nil || tmp.(string) == "" {
		return "", merror.ErrorUserIDNotFound
	}

	return tmp.(string), nil
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

type AuthorizedResource struct {
	Path   string
	Action Action
}
type AuthorizedResources []AuthorizedResource
type Action struct {
	Get    bool
	Post   bool
	Put    bool
	Delete bool
}

func GetAuthResources(mapScopes map[string]string, clientScope string) (*AuthorizedResources, string, error) {
	if clientScope == "" {
		return nil, "", merror.ErrorNotAllowedScop
	}

	allowed := ""
	found := false
	cs := strings.Split(clientScope, " ")
	var authResources AuthorizedResources
	for _, val := range cs {
		tmp := strings.Split(val, ":")
		tmpAct := Action{}
		if len(tmp) == 1 {
			tmpAct.Get = true
			tmpAct.Post = true
			tmpAct.Put = true
			tmpAct.Delete = true
		} else {
			switch tmp[1] {
			case "read":
				tmpAct.Get = true
			case "update":
				tmpAct.Post = true
			case "write":
				tmpAct.Put = true
			case "delete":
				tmpAct.Delete = true
			}
		}
		resources := strings.Split(mapScopes[tmp[0]], ",")
		found = false
		for _, res := range resources {
			authResources = append(authResources, AuthorizedResource{res, tmpAct})
			found = true
		}
		if found {
			allowed += val + " "
		}
	}

	return &authResources, strings.TrimSpace(allowed), nil
}

func IsAuthorized(authResources *AuthorizedResources, path, method string) (bool, error) {
	if authResources == nil {
		return false, errors.New("no authorized resources")
	}
	if path == "" {
		return false, errors.New("no path")
	}

	isAuthorized := false
	for _, res := range *authResources {
		if path == res.Path {
			if method == "GET" && res.Action.Get {
				isAuthorized = true
			} else if method == "POST" && res.Action.Post {
				isAuthorized = true
			} else if method == "PUT" && res.Action.Put {
				isAuthorized = true
			} else if method == "DELETE" && res.Action.Delete {
				isAuthorized = true
			}
		}
	}

	return isAuthorized, nil
}

type OAuthClient struct {
	// GetID() string
	// GetSecret() string
	// GetDomain() string
	// GetUserID() string

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
