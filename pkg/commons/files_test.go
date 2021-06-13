package commons_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wonksing/oauth-server/pkg/commons"
)

func TestFileExists(t *testing.T) {
	filename := "../../test/data/file_exists.txt"
	found := commons.FileExists(filename)
	if !assert.Equal(t, true, found) {
		t.FailNow()
	}

	filename = "../../test/data/file_not_exists.txt"
	found = commons.FileExists(filename)
	if !assert.Equal(t, false, found) {
		t.FailNow()
	}
}
