// Package tlv implements a tag-length-value encoding scheme for use in
// packing flat data structures with a fixed format. Bytes are
// encoded in big-endian format. Currently supports serialising the
// integer types and byte slices.
package tlv

// TODO(kyle): add Reader/Writer interfaces.
// TODO(kyle): add map encoding
// TODO(kyle): add structure encoding

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// TagUint8indicates a single byte.
	TagUint8 byte = iota + 1

	// TagInt8 indicates a signed byte.
	TagInt8

	// TagBytes indicates a variable length byte sequence.
	TagBytes

	// TagInt16 indicates a 16-bit signed integer.
	TagInt16

	// TagUint16 indicates a 16-bit unsigned integer.
	TagUint16

	// TagInt32 indicates a 32-bit signed integer.
	TagInt32

	// TagUint32 indicates a 32-bit unsigned integer.
	TagUint32

	// TagInt64 indicates a 64-bit signed integer.
	TagInt64

	// TagUint64 indicates a 64-bit signed integer.
	TagUint64
)

// Encoder is used to serialise values.
type Encoder struct {
	buf []byte
}

// Bytes returns the current data in the encoder.
func (enc *Encoder) Bytes() []byte {
	return enc.buf[:]
}

// Length returns the length of the encoded data.
func (enc *Encoder) Length() int {
	return len(enc.buf)
}

// Zero wipes the encoder's state and resets the encoder.
func (enc *Encoder) Zero() {
	l := len(enc.buf)
	for i := 0; i < l; i++ {
		enc.buf[i] ^= enc.buf[i]
	}

	enc.buf = nil
}

// NewFixedEncoder creates a new encoder with a fixed initial size.
func NewFixedEncoder(dataLength int, numRecords int) *Encoder {
	// Each record has five bytes of overhead.
	dataLength += (numRecords * 5)
	return &Encoder{
		buf: make([]byte, 0, dataLength),
	}
}

// Encode writes a value into the TLV. Note that this cannot be used
// to write messages or signatures.
func (enc *Encoder) Encode(v interface{}) error {
	var length [4]byte

	switch v := v.(type) {
	case int8:
		enc.buf = append(enc.buf, TagInt8)
		enc.buf = append(enc.buf, []byte{0, 0, 0, 1}...)
		enc.buf = append(enc.buf, byte(v))
	case uint8:
		enc.buf = append(enc.buf, TagUint8)
		enc.buf = append(enc.buf, []byte{0, 0, 0, 1}...)
		enc.buf = append(enc.buf, v)
	case []byte:
		enc.buf = append(enc.buf, TagBytes)
		binary.BigEndian.PutUint32(length[:], uint32(len(v)))
		enc.buf = append(enc.buf, length[:]...)
		enc.buf = append(enc.buf, v...)
	case int16:
		enc.buf = append(enc.buf, TagInt16)
		enc.buf = append(enc.buf, []byte{0, 0, 0, 2}...)

		var n [2]byte
		binary.BigEndian.PutUint16(n[:], uint16(v))
		enc.buf = append(enc.buf, n[:]...)
	case uint16:
		enc.buf = append(enc.buf, TagUint16)
		enc.buf = append(enc.buf, []byte{0, 0, 0, 2}...)

		var n [2]byte
		binary.BigEndian.PutUint16(n[:], v)
		enc.buf = append(enc.buf, n[:]...)
	case int32:
		enc.buf = append(enc.buf, TagInt32)
		enc.buf = append(enc.buf, []byte{0, 0, 0, 4}...)

		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(v))
		enc.buf = append(enc.buf, n[:]...)
	case uint32:
		enc.buf = append(enc.buf, TagUint32)
		enc.buf = append(enc.buf, []byte{0, 0, 0, 4}...)

		var n [4]byte
		binary.BigEndian.PutUint32(n[:], v)
		enc.buf = append(enc.buf, n[:]...)
	case int64:
		enc.buf = append(enc.buf, TagInt64)
		enc.buf = append(enc.buf, []byte{0, 0, 0, 8}...)

		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(v))
		enc.buf = append(enc.buf, n[:]...)
	case uint64:
		enc.buf = append(enc.buf, TagUint64)
		enc.buf = append(enc.buf, []byte{0, 0, 0, 8}...)

		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(v))
		enc.buf = append(enc.buf, n[:]...)
	default:
		return errors.New("tlv: unknown value")
	}

	return nil
}

const signatureLength = 64

// A Decoder parses a TLV-encoded structure.
type Decoder struct {
	buf []byte
}

// NewDecoder creates a decoder from a byte slice.
func NewDecoder(in []byte) *Decoder {
	return &Decoder{buf: in}
}

// Zero wipes and resets the decoder.
func (dec *Decoder) Zero() {
	l := len(dec.buf)
	for i := 0; i < l; i++ {
		dec.buf[i] = 0
	}

	dec.buf = nil
}

// Decode reads a value from the TLV.
func (dec *Decoder) Decode(v interface{}) error {
	buf := dec.buf

	var t uint8
	var l int32

	if len(buf) < 5 {
		return errors.New("tlv: invalid TLV-encoded data")
	}

	t = buf[0]
	l = int32(binary.BigEndian.Uint32(buf[1:5]))
	if l > int32(len(buf[5:])) {
		return errors.New("tlv: invalid data length")
	}

	if t == TagBytes && l == 0 {
		return nil
	}

	if v == nil {
		return errors.New("tlv: cannot decode into nil pointer")
	}

	buf = buf[5:]

	switch v := v.(type) {
	case *int8:
		if t != TagInt8 {
			return fmt.Errorf("tlv: invalid tag %d for data type", t)
		}
		*v = int8(buf[0])
	case *uint8:
		if t != TagUint8 {
			return fmt.Errorf("tlv: invalid tag %d for data type", t)
		}
		*v = buf[0]
	case *[]byte:
		if t != TagBytes {
			return fmt.Errorf("tlv: invalid tag %d for data type", t)
		}
		*v = make([]byte, int(l))
		copy(*v, buf)
	case *int16:
		if t != TagInt16 {
			return fmt.Errorf("tlv: invalid tag %d for data type", t)
		}
		*v = int16(binary.BigEndian.Uint16(buf[:2]))
	case *uint16:
		if t != TagUint16 {
			return fmt.Errorf("tlv: invalid tag %d for data type", t)
		}
		*v = binary.BigEndian.Uint16(buf[:2])
	case *int32:
		if t != TagInt32 {
			return fmt.Errorf("tlv: invalid tag %d for data type", t)
		}
		*v = int32(binary.BigEndian.Uint32(buf[:4]))
	case *uint32:
		if t != TagUint32 {
			return fmt.Errorf("tlv: invalid tag %d for data type", t)
		}
		*v = binary.BigEndian.Uint32(buf[:4])
	case *int64:
		if t != TagInt64 {
			return fmt.Errorf("tlv: invalid tag %d for data type", t)
		}
		*v = int64(binary.BigEndian.Uint64(buf[:8]))
	case *uint64:
		if t != TagUint64 {
			return fmt.Errorf("tlv: invalid tag %d for data type", t)
		}
		*v = binary.BigEndian.Uint64(buf[:8])
	default:
		return fmt.Errorf("tlv: cannot decode unknown tag %d", t)
	}

	dec.buf = buf[int(l):]
	return nil
}

// Length contains the length of the remaining encoded data in the
// decoder.
func (dec *Decoder) Length() int {
	return len(dec.buf)
}
