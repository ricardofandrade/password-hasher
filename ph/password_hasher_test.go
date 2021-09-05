package ph

import (
	"testing"
)

func Test_hashPassword(t *testing.T) {
	hasher := newPasswordHasher()
	hash, id := hasher.hashPassword("test")
	if id != 1 {
		t.Error("Expected the first id to be 1")
	}
	if hash != "7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==" {
		t.Errorf("Unexpected hash: %s", hash)
	}
	hash, id = hasher.hashPassword("angryMonkey")
	if id != 2 {
		t.Error("Expected the first id to be 2")
	}
	if hash != "ZEHhWB65gUlzdVwtDQArEyx+KVLzp/aTaRaPlBzYRIFj6vjFdqEb0Q5B8zVKCZ0vKbZPZklJz0Fd7su2A+gf7Q==" {
		t.Errorf("Unexpected hash: %s", hash)
	}
}
