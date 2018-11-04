package gosrs_test

import (
	"testing"

	"github.com/daliand/gosrs"
)

func TestForward(t *testing.T) {
	srs, _ := gosrs.GuardedScheme("Sekretkey")

	from := "bob@example.com"
	t.Logf("Original Address: %s", from)

	addr0, err0 := srs.Forward(from, "1sthop.com")
	if err0 != nil {
		t.Error(err0)
	}
	t.Logf("SRS0 Address: %s", addr0)

	addr1, err1 := srs.Forward(addr0, "2ndhop.com")
	if err1 != nil {
		t.Error(err1)
	}
	t.Logf("SRS1 Address: %s", addr1)

	srs2, _ := gosrs.GuardedScheme("SekretKey2")
	srs2.SetSeparator("+")

	addr2, err2 := srs2.Forward(addr1, "3rdhop.com")
	if err2 != nil {
		t.Error(err2)
	}
	t.Logf("SRS1 Address: %s", addr2)
}

func TestForwardReverse(t *testing.T) {
	srs, _ := gosrs.GuardedScheme("Sekretkey")

	// SRS0 address
	from := "bob@example.com"
	t.Logf("Original Address: %s", from)

	addr0, err0 := srs.Forward(from, "1sthop.com")
	if err0 != nil {
		t.Error(err0)
	}
	t.Logf("SRS0 Address: %s", addr0)

	addrr0, errr0 := srs.Reverse(addr0)
	if errr0 != nil {
		t.Fatal(errr0)
	}
	t.Logf("Reversed Address: %s", addrr0)

	addr1, err1 := srs.Forward(addr0, "2ndhop.com")
	if err1 != nil {
		t.Error(err1)
	}
	t.Logf("SRS1 Address: %s", addr1)

	addrr1, errr1 := srs.Reverse(addr1)
	if errr1 != nil {
		t.Fatal(errr1)
	}
	t.Logf("Reversed Address: %s", addrr1)
}

func TestForwardReverse2(t *testing.T) {
	srs, _ := gosrs.GuardedScheme("Sekretkey")

	addr0 := "srs0=ua6a=np=example.com=bob@1sthop.com"
	addrr0, errr0 := srs.Reverse(addr0)
	if errr0 != nil {
		t.Fatal(errr0)
	}
	t.Logf("Reversed Address: %s", addrr0)

	addr1, err1 := srs.Forward(addr0, "2ndhop.com")
	if err1 != nil {
		t.Error(err1)
	}
	t.Logf("SRS1 Address: %s", addr1)

	addrr1, errr1 := srs.Reverse(addr1)
	if errr1 != nil {
		t.Fatal(errr1)
	}
	t.Logf("Reversed Address: %s", addrr1)
}
