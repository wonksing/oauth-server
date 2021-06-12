package moauth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wonksing/oauth-server/pkg/models/moauth"
)

func TestGetUserIDContext(t *testing.T) {
	ctx := context.Background()
	userID, err := moauth.GetUserIDContext(ctx)
	if !assert.NotNil(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, "", userID) {
		t.FailNow()
	}

	ctx = moauth.WithUserIDContext(ctx, "wonk")
	userID, err = moauth.GetUserIDContext(ctx)
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, "wonk", userID) {
		t.FailNow()
	}

}

func TestGetAllowStatusContext(t *testing.T) {
	ctx := context.Background()
	allowStatus, err := moauth.GetAllowStatusContext(ctx)
	if !assert.NotNil(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, "", allowStatus) {
		t.FailNow()
	}

	ctx = moauth.WithAllowStatusContext(ctx, "yes")
	allowStatus, err = moauth.GetAllowStatusContext(ctx)
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, "yes", allowStatus) {
		t.FailNow()
	}

	ctx = moauth.WithAllowStatusContext(ctx, "no")
	_, err = moauth.GetAllowStatusContext(ctx)
	if !assert.NotNil(t, err) {
		t.FailNow()
	}

	ctx = moauth.WithAllowStatusContext(ctx, "")
	_, err = moauth.GetAllowStatusContext(ctx)
	if !assert.NotNil(t, err) {
		t.FailNow()
	}
}

func TestOAuthScope(t *testing.T) {
	s := moauth.NewOAuthScope()
	ar, err := s.Get("item")
	if !assert.NotNil(t, err) {
		t.FailNow()
	}
	if !assert.Empty(t, ar) {
		t.FailNow()
	}

	list := make(moauth.AuthorizedResources, 0)
	list = append(list, moauth.AuthorizedResource{"/item,/item/new", true, true, true, true})
	err = s.Set("item", list)
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	ar, err = s.Get("item")
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, "/item,/item/new", ar[0].Path) {
		t.FailNow()
	}

	allowedScope := s.PickAllowedScope("item item:read emp")
	if !assert.Equal(t, "item", allowedScope) {
		t.FailNow()
	}

	filteredScope, err := s.FilterScope(allowedScope, "item emp")
	if !assert.Nil(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, "item", filteredScope) {
		t.FailNow()
	}
}
