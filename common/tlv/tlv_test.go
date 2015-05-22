package tlv

import (
	"bytes"
	"fmt"
	"testing"
)

var (
	testEncoded []byte
	testMessage = []byte("Do not go gentle into that good night")
)

func TestTLVEncoding(t *testing.T) {
	enc := &Encoder{}

	err := enc.Encode(byte(1))
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = enc.Encode(int8(1))
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = enc.Encode(int16(4096))
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = enc.Encode(uint16(4096))
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = enc.Encode(int32(268435456))
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = enc.Encode(uint32(268435456))
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = enc.Encode(int64(1152921504606846976))
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = enc.Encode(uint64(1152921504606846976))
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = enc.Encode(testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	testEncoded = make([]byte, enc.Length())

	encoded := enc.Bytes()
	l := len(encoded)

	copy(testEncoded, enc.Bytes())
	enc.Zero()

	for i := 0; i < l; i++ {
		if encoded[i] != 0 {
			t.Fatal("tlv: encoder wasn't zeroised")
		}
	}
}

func TestDecoder(t *testing.T) {
	dec := NewDecoder(testEncoded)

	var b byte
	err := dec.Decode(&b)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if b != 1 {
		t.Fatalf("tlv: expected to decode byte = 1, but have %d", b)
	}

	var sb int8
	err = dec.Decode(&sb)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if b != 1 {
		t.Fatalf("tlv: expected to decode byte = 1, but have %d", b)
	}
	var i16 int16
	err = dec.Decode(&i16)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if i16 != 4096 {
		t.Fatalf("tlv: expected to decode int16 = 4096, but have %d", i16)
	}

	var u16 uint16
	err = dec.Decode(&u16)
	if err != nil {
		fmt.Printf("%x\n", dec.buf[:16])
		t.Fatalf("%v", err)
	}

	if u16 != 4096 {
		t.Fatalf("tlv: expected to decode uint16 = 4096, but have %d", u16)
	}

	var i32 int32
	err = dec.Decode(&i32)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if i32 != 268435456 {
		t.Fatalf("tlv: expected to decode int32 = 268435456, but have %d", i32)
	}

	var u32 uint32
	err = dec.Decode(&u32)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if u32 != 268435456 {
		t.Fatalf("tlv: expected to decode uint32 = 268435456, but have %d", u32)
	}

	var i64 int64
	err = dec.Decode(&i64)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if i64 != 1152921504606846976 {
		t.Fatalf("tlv: expected to decode int64 = 1152921504606846976, but have %d", i64)
	}

	var u64 uint64
	err = dec.Decode(&u64)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if u64 != 1152921504606846976 {
		t.Fatalf("tlv: expected to decode uint64 = 1152921504606846976, but have %d", u64)
	}

	var bs []byte
	err = dec.Decode(&bs)
	if err != nil {
		fmt.Printf("%x\n", dec.buf)
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(bs, testMessage) {
		t.Fatalf("tlv: expected to decode bytes '%s', but have '%s'",
			testMessage, bs)
	}
}

func TestEncodeFail(t *testing.T) {
	enc := &Encoder{}
	m := map[string]string{}

	if err := enc.Encode(m); err == nil {
		t.Fatal("tlv: encode should fail on unknown type")
	}
}

func TestDecodeFails(t *testing.T) {
	enc := &Encoder{}

	enc.Encode(uint16(42))
	enc.Encode(int16(32))
	out := enc.Bytes()

	tmp := make([]byte, len(out))
	copy(tmp, out)
	dec := NewDecoder(tmp)

	var b byte
	if err := dec.Decode(&b); err == nil {
		t.Fatal("tlv: expect failure with wrong tag type")
	}

	var sb int8
	if err := dec.Decode(&sb); err == nil {
		t.Fatal("tlv: expect failure with wrong tag type")
	}

	var bs []byte
	if err := dec.Decode(&bs); err == nil {
		t.Fatal("tlv: expect failure with wrong tag type")
	}

	var i16 int16
	if err := dec.Decode(&i16); err == nil {
		t.Fatal("tlv: expect failure with wrong tag type")
	}

	var i32 int32
	if err := dec.Decode(&i32); err == nil {
		t.Fatal("tlv: expect failure with wrong tag type")
	}

	var u32 uint32
	if err := dec.Decode(&u32); err == nil {
		t.Fatal("tlv: expect failure with wrong tag type")
	}

	var i64 int64
	if err := dec.Decode(&i64); err == nil {
		t.Fatal("tlv: expect failure with wrong tag type")
	}

	var u64 uint64
	if err := dec.Decode(&u64); err == nil {
		t.Fatal("tlv: expect failure with wrong tag type")
	}

	var u16 uint16
	if err := dec.Decode(&u16); err != nil {
		t.Fatalf("%v", err)
	}

	if err := dec.Decode(&u16); err == nil {
		t.Fatal("tlv: expect failure with wrong tag type")
	}

	if dec.Length() != 7 {
		t.Fatalf("tlv: expect 7 bytes remaining in decoder, have %d", dec.Length())
	}

	dec2 := NewDecoder(dec.buf[:4])
	if err := dec2.Decode(&u16); err == nil {
		t.Fatal("tlv: expect decode to fail with too few bytes")
	}

	dec2.Zero()

	v := dec.buf[1]
	dec.buf[1] = 'A'
	if err := dec.Decode(&i16); err == nil {
		t.Fatal("tlv: expect decode to fail with too invalid length")
	}
	dec.buf[1] = v

	if err := dec.Decode(i16); err == nil {
		t.Fatal("tlv: expect decode to fail with non-pointer")
	}

	m := map[string]string{}
	if err := dec.Decode(&m); err == nil {
		t.Fatal("tlv: expect decode to fail with unknown value")
	}

	if err := dec.Decode(nil); err == nil {
		t.Fatal("tlv: expect decode to fail with nil pointer")
	}
}

func TestFixedEncoder(t *testing.T) {
	expLen := 10 + (2 * len(testMessage))

	enc := NewFixedEncoder(len(testMessage)+len(testMessage), 2)
	if cap(enc.buf) != expLen {
		t.Fatalf("tlv: expected capacity of fixed encoder to be %d, but it is %d",
			expLen, cap(enc.buf))
	}

	err := enc.Encode(testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = enc.Encode(testMessage)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if cap(enc.buf) != expLen {
		t.Fatalf("tlv: expected capacity of fixed encoder to be %d, but it is %d",
			expLen, cap(enc.buf))
	}

	if len(enc.buf) != expLen {
		t.Fatalf("tlv: expected length of fixed encoder to be %d, but it is %d",
			expLen, len(enc.buf))
	}

	if enc.Length() != expLen {
		t.Fatalf("tlv: expected length of fixed encoder to be %d, but it is %d",
			expLen, enc.Length())
	}
}

func TestZeroLengthBuffer(t *testing.T) {
	enc := &Encoder{}
	var bs []byte

	err := enc.Encode(bs)
	if err != nil {
		t.Fatalf("%v", err)
	}

	dec := NewDecoder(enc.Bytes())
	err = dec.Decode(&bs)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if len(bs) != 0 {
		t.Fatalf("tlv: should have read a zero-length buffer")
	}
}
