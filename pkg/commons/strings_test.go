package commons_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wonksing/oauth-server/pkg/commons"
)

func TestRandStringRunes(t *testing.T) {
	s := commons.RandStringRunes(2)

	if !assert.Equal(t, 2, len(s)) {
		t.FailNow()
	}
}

func TestRandStringBytes(t *testing.T) {
	s := commons.RandStringBytes(2)
	if !assert.Equal(t, 2, len(s)) {
		t.FailNow()
	}
}
