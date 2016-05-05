// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Represents JSON data structure using native Go types: booleans, floats,
// strings, arrays, and maps.

package ubjson

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strconv"

	"github.com/golang/glog"
)

// Unmarshal parses the JSON-encoded data and stores the result
// in the value pointed to by v.
//
// Unmarshal uses the inverse of the encodings that
// Marshal uses, allocating maps, slices, and pointers as necessary,
// with the following additional rules:
//
// To unmarshal JSON into a pointer, Unmarshal first handles the case of
// the JSON being the JSON literal null.  In that case, Unmarshal sets
// the pointer to nil.  Otherwise, Unmarshal unmarshals the JSON into
// the value pointed at by the pointer.  If the pointer is nil, Unmarshal
// allocates a new value for it to point to.
//
// To unmarshal JSON into a struct, Unmarshal matches incoming object
// keys to the keys used by Marshal (either the struct field name or its tag),
// preferring an exact match but also accepting a case-insensitive match.
//
// To unmarshal JSON into an interface value,
// Unmarshal stores one of these in the interface value:
//
//	bool, for JSON booleans
//	float64, for JSON numbers
//	string, for JSON strings
//	[]interface{}, for JSON arrays
//	map[string]interface{}, for JSON objects
//	nil for JSON null
//
// To unmarshal a JSON array into a slice, Unmarshal resets the slice to nil
// and then appends each element to the slice.
//
// To unmarshal a JSON object into a map, Unmarshal replaces the map
// with an empty map and then adds key-value pairs from the object to
// the map.
//
// If a JSON value is not appropriate for a given target type,
// or if a JSON number overflows the target type, Unmarshal
// skips that field and completes the unmarshalling as best it can.
// If no more serious errors are encountered, Unmarshal returns
// an UnmarshalTypeError describing the earliest such error.
//
// The JSON null value unmarshals into an interface, map, pointer, or slice
// by setting that Go value to nil. Because null is often used in JSON to mean
// ``not present,'' unmarshaling a JSON null into any other Go type has no effect
// on the value and produces no error.
//
// When unmarshaling quoted strings, invalid UTF-8 or
// invalid UTF-16 surrogate pairs are not treated as an error.
// Instead, they are replaced by the Unicode replacement
// character U+FFFD.
//
func Unmarshal(data []byte, v interface{}) error {
	// Check for well-formedness.
	// Avoids filling out half a data structure
	// before discovering a JSON syntax error.
	var d decodeState
	err := checkValid(data, &d.scan)
	if err != nil {
		return err
	}

	d.init(data)
	return d.unmarshal(v)
}

// Unmarshaler is the interface implemented by objects
// that can unmarshal a JSON description of themselves.
// The input can be assumed to be a valid encoding of
// a JSON value. UnmarshalJSON must copy the JSON data
// if it wishes to retain the data after returning.
type Unmarshaler interface {
	UnmarshalUBJSON([]byte) error
}

// An UnmarshalTypeError describes a JSON value that was
// not appropriate for a value of a specific Go type.
type UnmarshalTypeError struct {
	Value  string       // description of JSON value - "bool", "array", "number -5"
	Type   reflect.Type // type of Go value it could not be assigned to
	Offset int64        // error occurred after reading Offset bytes
}

func (e *UnmarshalTypeError) Error() string {
	return "json: cannot unmarshal " + e.Value + " into Go value of type " + e.Type.String()
}

// An UnmarshalFieldError describes a JSON object key that
// led to an unexported (and therefore unwritable) struct field.
// (No longer used; kept for compatibility.)
type UnmarshalFieldError struct {
	Key   string
	Type  reflect.Type
	Field reflect.StructField
}

func (e *UnmarshalFieldError) Error() string {
	return "json: cannot unmarshal object key " + strconv.Quote(e.Key) + " into unexported field " + e.Field.Name + " of type " + e.Type.String()
}

// An InvalidUnmarshalError describes an invalid argument passed to Unmarshal.
// (The argument to Unmarshal must be a non-nil pointer.)
type InvalidUnmarshalError struct {
	Type reflect.Type
}

func (e *InvalidUnmarshalError) Error() string {
	if e.Type == nil {
		return "json: Unmarshal(nil)"
	}

	if e.Type.Kind() != reflect.Ptr {
		return "json: Unmarshal(non-pointer " + e.Type.String() + ")"
	}
	return "json: Unmarshal(nil " + e.Type.String() + ")"
}

func (d *decodeState) unmarshal(v interface{}) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			err = r.(error)
		}
	}()

	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return &InvalidUnmarshalError{reflect.TypeOf(v)}
	}

	d.scan.reset()
	// We decode rv not rv.Elem because the Unmarshaler interface
	// test must be applied at the top level of the value.
	d.value(rv, d.scanOnce())
	return d.savedError
}

// decodeState represents the state while decoding a JSON value.
type decodeState struct {
	data       []byte
	off        int // read offset in data
	scan       scanner
	nextscan   scanner // for calls to nextValue
	savedError error
	useNumber  bool
}

// errPhase is used for errors that should not happen unless
// there is a bug in the JSON decoder or something is editing
// the data slice while the decoder executes.
var errPhase = errors.New("JSON decoder out of sync - data changing underfoot?")

func (d *decodeState) init(data []byte) *decodeState {
	d.data = data
	d.off = 0
	d.savedError = nil
	return d
}

// error aborts the decoding by panicking with err.
func (d *decodeState) error(err error) {
	panic(err)
}

// saveError saves the first err it is called with,
// for reporting at the end of the unmarshal.
func (d *decodeState) saveError(err error) {
	if d.savedError == nil {
		d.savedError = err
	}
}

// next cuts off and returns the next full JSON value in d.data[d.off:].
// The next value is known to be an object or array, not a literal.
func (d *decodeState) next() []byte {
	item, _, err := nextValue(d.data[d.off:], &d.nextscan)
	if err != nil {
		d.error(err)
	}
	for range item {
		d.scanOnce()
	}
	return item
}

func (d *decodeState) scanOnce() int {
	var r int
	if d.off >= len(d.data) {
		r = d.scan.eof()
		d.off = len(d.data) + 1 // mark processed EOF with len+1
	} else {
		c := int(d.data[d.off])
		d.off++
		r = d.scan.step(&d.scan, c)
		if r == scanError {
			glog.V(3).Infof("Error: %s\nStack: %+#v", d.scan.err, d.scan.parseState)
		}
	}
	return r
}

// scanWhile processes bytes in d.data[d.off:] until it
// receives a scan code not equal to op.
// It updates d.off and returns the new scan code.
func (d *decodeState) scanWhile(op int) int {
	var newOp int
	for {
		newOp = d.scanOnce()
		if newOp != op {
			break
		}
	}
	return newOp
}

func (d *decodeState) scanPayload() ([]byte, error) {
	start := d.off
	op := d.scanWhile(scanContinue)
	if op != scanEndPayload {
		glog.V(3).Infof("expected endPayload, got %d", op)
		return nil, errPhase
	}
	return d.data[start:d.off], nil
}

func (d *decodeState) scanString() (string, error) {
	l, err := d.scanInt(d.scanOnce())
	if err != nil {
		return "", err
	}
	if l == 0 {
		// endPayload is not generated for an empty string.
		return "", nil
	}
	s, err := d.scanPayload()
	if err != nil {
		return "", err
	}
	if len(s) != int(l) {
		return "", fmt.Errorf("INTERNAL: expected %d bytes, got %d", l, len(s))
	}
	// UBJSON mandates UTF-8 strings and Go uses UTF-8 for string representation.
	return string(s), nil
}

func (d *decodeState) scanInt(t int) (int64, error) {
	switch t {
	case scanInt8, scanUint8, scanInt16, scanInt32, scanInt64:
	default:
		return 0, fmt.Errorf("expected int type, got %s", scanToName[t])
	}
	payload, err := d.scanPayload()
	if err != nil {
		return 0, err
	}
	// Assuming that payload has correct length.
	switch t {
	case scanInt8:
		return int64(int8(payload[0])), nil
	case scanUint8:
		return int64(uint8(payload[0])), nil
	case scanInt16:
		var v int16
		if err := binary.Read(bytes.NewBuffer(payload), binary.BigEndian, &v); err != nil {
			glog.V(3).Infof("Invalid int value: %s", err)
			return 0, err
		}
		return int64(v), nil
	case scanInt32:
		var v int32
		if err := binary.Read(bytes.NewBuffer(payload), binary.BigEndian, &v); err != nil {
			glog.V(3).Infof("Invalid int value: %s", err)
			return 0, err
		}
		return int64(v), nil
	case scanInt64:
		var v int64
		if err := binary.Read(bytes.NewBuffer(payload), binary.BigEndian, &v); err != nil {
			glog.V(3).Infof("Invalid int value: %s", err)
			return 0, err
		}
		return v, nil
	}
	panic("unreachable")
	return 0, nil
}

// value decodes a JSON value from d.data[d.off:] into the value.
// it updates d.off to point past the decoded value.
func (d *decodeState) value(v reflect.Value, op int) {
	if !v.IsValid() {
		_, rest, err := nextValue(d.data[d.off-1:], &d.nextscan)
		if err != nil {
			d.error(err)
		}
		d.off = len(d.data) - len(rest)
		endValue(&d.scan)
		return
	}

	switch op {
	default:
		glog.V(3).Infof("want beginLiteral, beginObject or beginArray, got %s", scanToName[op])
		d.error(errPhase)

	case scanBeginArray:
		d.array(v)

	case scanBeginObject:
		d.object(v)

	case scanNull, scanTrue, scanFalse, scanInt8, scanUint8, scanInt16, scanInt32, scanInt64, scanBignum, scanString, scanFloat32, scanFloat64, scanChar:
		d.literal(v, op)
	}
}

type jsonUnmarshaler struct {
	v json.Unmarshaler
}

func (j *jsonUnmarshaler) UnmarshalUBJSON(b []byte) error {
	var v interface{}
	if err := Unmarshal(b, &v); err != nil {
		return err
	}
	b, err := json.Marshal(&v)
	if err != nil {
		return err
	}
	return j.v.UnmarshalJSON(b)
}

// indirect walks down v allocating pointers as needed,
// until it gets to a non-pointer.
// if it encounters an Unmarshaler, indirect stops and returns that.
// if decodingNull is true, indirect stops at the last pointer so it can be set to nil.
func (d *decodeState) indirect(v reflect.Value, decodingNull bool) (Unmarshaler, encoding.TextUnmarshaler, reflect.Value) {
	// If v is a named type and is addressable,
	// start with its address, so that if the type has pointer methods,
	// we find them.
	if v.Kind() != reflect.Ptr && v.Type().Name() != "" && v.CanAddr() {
		v = v.Addr()
	}
	for {
		// Load value from interface, but only if the result will be
		// usefully addressable.
		if v.Kind() == reflect.Interface && !v.IsNil() {
			e := v.Elem()
			if e.Kind() == reflect.Ptr && !e.IsNil() && (!decodingNull || e.Elem().Kind() == reflect.Ptr) {
				v = e
				continue
			}
		}

		if v.Kind() != reflect.Ptr {
			break
		}

		if v.Elem().Kind() != reflect.Ptr && decodingNull && v.CanSet() {
			break
		}
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		if v.Type().NumMethod() > 0 {
			if u, ok := v.Interface().(Unmarshaler); ok {
				return u, nil, reflect.Value{}
			}
			if u, ok := v.Interface().(json.Unmarshaler); ok {
				return &jsonUnmarshaler{u}, nil, reflect.Value{}
			}
			if u, ok := v.Interface().(encoding.TextUnmarshaler); ok {
				return nil, u, reflect.Value{}
			}
		}
		v = v.Elem()
	}
	return nil, nil, v
}

// array consumes an array from d.data[d.off-1:], decoding into the value v.
// the first byte of the array ('[') has been read already.
func (d *decodeState) array(v reflect.Value) {
	// Check for unmarshaler.
	u, ut, pv := d.indirect(v, false)
	if u != nil {
		d.off--
		d.scan.undo(scanBeginArray)
		b := d.next()
		if err := u.UnmarshalUBJSON(b); err != nil {
			d.error(err)
		}
		return
	}
	if ut != nil {
		d.saveError(&UnmarshalTypeError{"array", v.Type(), int64(d.off)})
		d.off--
		d.next()
		return
	}

	v = pv

	// Check type of target.
	switch v.Kind() {
	case reflect.Interface:
		if v.NumMethod() == 0 {
			// Decoding into nil interface?  Switch to non-reflect code.
			v.Set(reflect.ValueOf(d.arrayInterface()))
			return
		}
		// Otherwise it's invalid.
		fallthrough
	default:
		d.saveError(&UnmarshalTypeError{"array", v.Type(), int64(d.off)})
		d.off--
		d.next()
		return
	case reflect.Array:
	case reflect.Slice:
		break
	}

	op := d.scanOnce()
	var (
		itemType, itemCount int
		hasCount, hasType   bool
	)
	if op == scanEndArray {
		return
	}
	if op == scanContainerType {
		switch d.scanOnce() {
		case scanEndPayload:
			t, err := scanTypeFromByte(d.data[d.off-1])
			if err != nil {
				d.error(err)
				return
			}
			itemType = t
		default:
			d.error(errPhase)
			return
		}
		hasType = true
		op = d.scanOnce()
		if op != scanContainerLen {
			d.error(fmt.Errorf("expected length after type, got %s", scanToName[op]))
			return
		}
	}
	if op == scanContainerLen {
		l, err := d.scanInt(d.scanOnce())
		if err != nil {
			d.error(fmt.Errorf("invalid array length: %s", err))
			return
		}
		itemCount = int(l)
		hasCount = true
	} else {
		// If we don't have length, `op` must be the type tag of the first item.
		d.off--
		d.scan.undo(op)
	}
	if hasCount && v.Kind() == reflect.Slice {
		// Grow the slice once if we know how many items there will be.
		newv := reflect.MakeSlice(v.Type(), v.Len(), itemCount)
		reflect.Copy(newv, v)
		v.Set(newv)
	}
	// TODO(imax): add a special case for byte array.

	i := 0
	for {
		if hasCount && i >= itemCount {
			break
		}

		if !hasCount {
			// Look ahead for ].
			op := d.scanOnce()
			if op == scanEndArray {
				break
			}
			d.off--
			d.scan.undo(op)
		}

		// Get element of array, growing if necessary.
		if v.Kind() == reflect.Slice {
			// Grow slice if necessary
			if i >= v.Cap() {
				newcap := v.Cap() + v.Cap()/2
				if newcap < 4 {
					newcap = 4
				}
				newv := reflect.MakeSlice(v.Type(), v.Len(), newcap)
				reflect.Copy(newv, v)
				v.Set(newv)
			}
			if i >= v.Len() {
				v.SetLen(i + 1)
			}
		}

		var op int
		if hasType {
			op = itemType
		} else {
			op = d.scanOnce()
		}
		if i < v.Len() {
			// Decode into element.
			d.value(v.Index(i), op)
		} else {
			// Ran out of fixed array: skip.
			d.value(reflect.Value{}, op)
		}
		i++
	}

	if i < v.Len() {
		if v.Kind() == reflect.Array {
			// Array.  Zero the rest.
			z := reflect.Zero(v.Type().Elem())
			for ; i < v.Len(); i++ {
				v.Index(i).Set(z)
			}
		} else {
			v.SetLen(i)
		}
	}
	if i == 0 && v.Kind() == reflect.Slice {
		v.Set(reflect.MakeSlice(v.Type(), 0, 0))
	}
}

// object consumes an object from d.data[d.off-1:], decoding into the value v.
// the first byte ('{') of the object has been read already.
func (d *decodeState) object(v reflect.Value) {
	// Check for unmarshaler.
	u, ut, pv := d.indirect(v, false)
	if u != nil {
		d.off--
		d.scan.undo(scanBeginObject)
		b := d.next()
		if err := u.UnmarshalUBJSON(b); err != nil {
			d.error(err)
		}
		return
	}
	if ut != nil {
		d.saveError(&UnmarshalTypeError{"object", v.Type(), int64(d.off)})
		d.off--
		d.next() // skip over { } in input
		return
	}
	v = pv

	// Decoding into nil interface?  Switch to non-reflect code.
	if v.Kind() == reflect.Interface && v.NumMethod() == 0 {
		v.Set(reflect.ValueOf(d.objectInterface()))
		return
	}

	// Check type of target: struct or map[string]T
	switch v.Kind() {
	case reflect.Map:
		// map must have string kind
		t := v.Type()
		if t.Key().Kind() != reflect.String {
			d.saveError(&UnmarshalTypeError{"object", v.Type(), int64(d.off)})
			d.off--
			d.next() // skip over { } in input
			return
		}
		if v.IsNil() {
			v.Set(reflect.MakeMap(t))
		}
	case reflect.Struct:

	default:
		d.saveError(&UnmarshalTypeError{"object", v.Type(), int64(d.off)})
		d.off--
		d.next() // skip over { } in input
		return
	}

	op := d.scanOnce()
	var (
		itemType, itemCount int
		hasCount, hasType   bool
	)
	if op == scanEndObject {
		return
	}
	if op == scanContainerType {
		switch d.scanOnce() {
		case scanEndPayload:
			t, err := scanTypeFromByte(d.data[d.off-1])
			if err != nil {
				d.error(err)
				return
			}
			itemType = t
		default:
			d.error(errPhase)
			return
		}
		hasType = true
		op = d.scanOnce()
		if op != scanContainerLen {
			d.error(fmt.Errorf("expected length after type, got %s", scanToName[op]))
			return
		}
	}
	if op == scanContainerLen {
		l, err := d.scanInt(d.scanOnce())
		if err != nil {
			d.error(fmt.Errorf("invalid array length: %s", err))
			return
		}
		itemCount = int(l)
		hasCount = true
	} else {
		// If we don't have length, `op` must be the type tag of the length of the first key.
		d.off--
		d.scan.undo(op)
	}

	var mapElem reflect.Value

	for ; !hasCount || itemCount > 0; itemCount-- {
		if !hasCount {
			// Read opening " of string key or closing }.
			op := d.scanOnce()
			if op == scanEndObject {
				// closing } - can only happen on first iteration.
				break
			}
			d.off--
			d.scan.undo(op)
		}

		key, err := d.scanString()
		if err != nil {
			d.error(err)
			break
		}

		// Figure out field corresponding to key.
		var subv reflect.Value

		if v.Kind() == reflect.Map {
			elemType := v.Type().Elem()
			if !mapElem.IsValid() {
				mapElem = reflect.New(elemType).Elem()
			} else {
				mapElem.Set(reflect.Zero(elemType))
			}
			subv = mapElem
		} else {
			var f *field
			fields := cachedTypeFields(v.Type())
			for i := range fields {
				ff := &fields[i]
				if bytes.Equal(ff.nameBytes, []byte(key)) {
					f = ff
					break
				}
				if f == nil && ff.equalFold(ff.nameBytes, []byte(key)) {
					f = ff
				}
			}
			if f != nil {
				subv = v
				for _, i := range f.index {
					if subv.Kind() == reflect.Ptr {
						if subv.IsNil() {
							subv.Set(reflect.New(subv.Type().Elem()))
						}
						subv = subv.Elem()
					}
					subv = subv.Field(i)
				}
			}
		}

		if hasType {
			d.value(subv, itemType)
		} else {
			d.value(subv, d.scanOnce())
		}

		// Write value back to map;
		// if using struct, subv points into struct already.
		if v.Kind() == reflect.Map {
			kv := reflect.ValueOf(key).Convert(v.Type().Key())
			v.SetMapIndex(kv, subv)
		}
	}
}

// convertNumber converts the number literal s to a float64 or a Number
// depending on the setting of d.useNumber.
func (d *decodeState) convertNumber(s string) (interface{}, error) {
	if d.useNumber {
		return json.Number(s), nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, &UnmarshalTypeError{"number " + s, reflect.TypeOf(0.0), int64(d.off)}
	}
	return f, nil
}

var numberType = reflect.TypeOf(json.Number(""))

// literalStore decodes a literal stored in item into v.
func (d *decodeState) literal(v reflect.Value, op int) {
	// Check for unmarshaler.
	wantptr := op == scanNull // null
	u, ut, pv := d.indirect(v, wantptr)
	if u != nil {
		d.off--
		d.scan.undo(op)
		b := d.next()
		if err := u.UnmarshalUBJSON(b); err != nil {
			d.error(err)
		}
		return
	}
	if ut != nil {
		if op != scanString {
			d.saveError(&UnmarshalTypeError{"string", v.Type(), int64(d.off)})
			return
		}
		s, err := d.scanString()
		if err != nil {
			glog.V(3).Infof("invalid string: %s", err)
			d.error(errPhase)
		}
		err = ut.UnmarshalText([]byte(s))
		if err != nil {
			d.error(err)
		}
		return
	}

	v = pv

	switch op {
	default:
		d.saveError(&UnmarshalTypeError{scanToName[op], v.Type(), int64(d.off)})
	case scanNull:
		switch v.Kind() {
		case reflect.Interface, reflect.Ptr, reflect.Map, reflect.Slice:
			v.Set(reflect.Zero(v.Type()))
			// otherwise, ignore null for primitives/string
		}
	case scanTrue, scanFalse:
		value := op == scanTrue
		switch v.Kind() {
		default:
			d.saveError(&UnmarshalTypeError{"bool", v.Type(), int64(d.off)})
		case reflect.Bool:
			v.SetBool(value)
		case reflect.Interface:
			if v.NumMethod() == 0 {
				v.Set(reflect.ValueOf(value))
			} else {
				d.saveError(&UnmarshalTypeError{"bool", v.Type(), int64(d.off)})
			}
		}

	case scanString:
		s, err := d.scanString()
		if err != nil {
			glog.V(3).Infof("invalid string: %s", err)
			d.error(errPhase)
		}
		switch v.Kind() {
		default:
			d.saveError(&UnmarshalTypeError{"string", v.Type(), int64(d.off)})
		case reflect.Slice:
			if v.Type().Elem().Kind() != reflect.Uint8 {
				d.saveError(&UnmarshalTypeError{"string", v.Type(), int64(d.off)})
				break
			}
			b := []byte(s)
			v.Set(reflect.ValueOf(b))
		case reflect.String:
			v.SetString(string(s))
		case reflect.Interface:
			if v.NumMethod() == 0 {
				v.Set(reflect.ValueOf(string(s)))
			} else {
				d.saveError(&UnmarshalTypeError{"string", v.Type(), int64(d.off)})
			}
		}

	case scanInt8, scanUint8, scanInt16, scanInt32, scanInt64:
		n, err := d.scanInt(op)
		if err != nil {
			d.error(err)
			break
		}
		switch v.Kind() {
		default:
			d.error(&UnmarshalTypeError{"number", v.Type(), int64(d.off)})
		case reflect.Interface:
			if v.NumMethod() != 0 {
				d.saveError(&UnmarshalTypeError{"number", v.Type(), int64(d.off)})
				break
			}
			v.Set(reflect.ValueOf(n))

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if v.OverflowInt(n) {
				d.saveError(&UnmarshalTypeError{"number", v.Type(), int64(d.off)})
				break
			}
			v.SetInt(n)

		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			if v.OverflowUint(uint64(n)) {
				d.saveError(&UnmarshalTypeError{"number ", v.Type(), int64(d.off)})
				break
			}
			v.SetUint(uint64(n))
		case reflect.Float32, reflect.Float64:
			if v.OverflowFloat(float64(n)) {
				d.saveError(&UnmarshalTypeError{"number ", v.Type(), int64(d.off)})
				break
			}
			v.SetFloat(float64(n))
		}
	case scanFloat32:
		b, err := d.scanPayload()
		if err != nil {
			d.error(err)
			return
		}
		var n float32
		if err := binary.Read(bytes.NewBuffer(b), binary.BigEndian, &n); err != nil {
			d.error(err)
			return
		}
		switch v.Kind() {
		default:
			d.error(&UnmarshalTypeError{"number", v.Type(), int64(d.off)})
		case reflect.Interface:
			if v.NumMethod() != 0 {
				d.saveError(&UnmarshalTypeError{"number", v.Type(), int64(d.off)})
				break
			}
			v.Set(reflect.ValueOf(n))

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if v.OverflowInt(int64(n)) {
				d.saveError(&UnmarshalTypeError{"number", v.Type(), int64(d.off)})
				break
			}
			v.SetInt(int64(n))

		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			if v.OverflowUint(uint64(n)) {
				d.saveError(&UnmarshalTypeError{"number ", v.Type(), int64(d.off)})
				break
			}
			v.SetUint(uint64(n))
		case reflect.Float32, reflect.Float64:
			if v.OverflowFloat(float64(n)) {
				d.saveError(&UnmarshalTypeError{"number ", v.Type(), int64(d.off)})
				break
			}
			v.SetFloat(float64(n))
		}
	case scanFloat64:
		b, err := d.scanPayload()
		if err != nil {
			d.error(err)
			return
		}
		var n float64
		if err := binary.Read(bytes.NewBuffer(b), binary.BigEndian, &n); err != nil {
			d.error(err)
			return
		}
		switch v.Kind() {
		default:
			d.error(&UnmarshalTypeError{"number", v.Type(), int64(d.off)})
		case reflect.Interface:
			if v.NumMethod() != 0 {
				d.saveError(&UnmarshalTypeError{"number", v.Type(), int64(d.off)})
				break
			}
			v.Set(reflect.ValueOf(n))

		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if v.OverflowInt(int64(n)) {
				d.saveError(&UnmarshalTypeError{"number", v.Type(), int64(d.off)})
				break
			}
			v.SetInt(int64(n))

		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
			if v.OverflowUint(uint64(n)) {
				d.saveError(&UnmarshalTypeError{"number ", v.Type(), int64(d.off)})
				break
			}
			v.SetUint(uint64(n))
		case reflect.Float32, reflect.Float64:
			if v.OverflowFloat(n) {
				d.saveError(&UnmarshalTypeError{"number ", v.Type(), int64(d.off)})
				break
			}
			v.SetFloat(n)
		}
	}
}

// The xxxInterface routines build up a value to be stored
// in an empty interface.  They are not strictly necessary,
// but they avoid the weight of reflection in this common case.

// valueInterface is like value but returns interface{}
func (d *decodeState) valueInterface(op int) interface{} {
	switch op {
	default:
		d.error(errPhase)
		panic("unreachable")
	case scanBeginArray:
		return d.arrayInterface()
	case scanBeginObject:
		return d.objectInterface()
	case scanNull:
		return nil
	case scanTrue:
		return true
	case scanFalse:
		return false
	case scanInt8, scanUint8, scanInt16, scanInt32, scanInt64:
		v, err := d.scanInt(op)
		if err != nil {
			d.error(err)
			return nil
		}
		// TODO(imax): return values of different types, not only int64?
		return v
	case scanBignum, scanString:
		v, err := d.scanString()
		if err != nil {
			d.error(err)
			return nil
		}
		// TODO(imax): parse big numbers.
		return v
	case scanFloat32, scanFloat64:
		b, err := d.scanPayload()
		if err != nil {
			d.error(err)
			return nil
		}
		switch op {
		case scanFloat32:
			var v float32
			if err := binary.Read(bytes.NewBuffer(b), binary.BigEndian, &v); err != nil {
				d.error(err)
				return nil
			}
			return v
		case scanFloat64:
			var v float64
			if err := binary.Read(bytes.NewBuffer(b), binary.BigEndian, &v); err != nil {
				d.error(err)
				return nil
			}
			return v
		}
	case scanChar:
		b, err := d.scanPayload()
		if err != nil {
			d.error(err)
			return nil
		}
		if len(b) != 1 {
			d.error(fmt.Errorf("expected 1 byte payload, got %d bytes", len(b)))
			return nil
		}
		return b[0]
	}
	panic("unreachable")
	return nil
}

// arrayInterface is like array but returns []interface{}.
func (d *decodeState) arrayInterface() []interface{} {
	var v = make([]interface{}, 0)
	op := d.scanOnce()
	var (
		itemType, itemCount int
		hasCount, hasType   bool
	)
	if op == scanEndArray {
		return v
	}
	if op == scanContainerType {
		switch d.scanOnce() {
		case scanEndPayload:
			t, err := scanTypeFromByte(d.data[d.off-1])
			if err != nil {
				d.error(err)
				return nil
			}
			itemType = t
		default:
			d.error(errPhase)
			return nil
		}
		hasType = true
		op = d.scanOnce()
		if op != scanContainerLen {
			d.error(fmt.Errorf("expected length after type, got %s", scanToName[op]))
			return nil
		}
	}
	if op == scanContainerLen {
		l, err := d.scanInt(d.scanOnce())
		if err != nil {
			d.error(fmt.Errorf("invalid array length: %s", err))
			return nil
		}
		itemCount = int(l)
		hasCount = true
	} else {
		// If we don't have length, `op` must be the type tag of the first item.
		v = append(v, d.valueInterface(op))
	}
	// TODO(imax): add a special case for byte array.

	if hasCount {
		for ; itemCount > 0; itemCount-- {
			if hasType {
				v = append(v, d.valueInterface(itemType))
			} else {
				v = append(v, d.valueInterface(d.scanOnce()))
			}
		}
	} else {
		for {
			op := d.scanOnce()
			if op == scanEndArray {
				break
			}
			// TODO(imax): check for errors, otherwise we will stuck here until OOM.
			v = append(v, d.valueInterface(op))
		}
	}
	return v
}

// objectInterface is like object but returns map[string]interface{}.
func (d *decodeState) objectInterface() map[string]interface{} {
	m := make(map[string]interface{})
	op := d.scanOnce()
	var (
		itemType, itemCount int
		hasCount, hasType   bool
	)
	if op == scanEndObject {
		return m
	}
	if op == scanContainerType {
		switch d.scanOnce() {
		case scanEndPayload:
			t, err := scanTypeFromByte(d.data[d.off-1])
			if err != nil {
				d.error(err)
				return nil
			}
			itemType = t
		default:
			d.error(errPhase)
			return nil
		}
		hasType = true
		op = d.scanOnce()
		if op != scanContainerLen {
			d.error(fmt.Errorf("expected length after type, got %s", scanToName[op]))
			return nil
		}
	}
	if op == scanContainerLen {
		l, err := d.scanInt(d.scanOnce())
		if err != nil {
			d.error(fmt.Errorf("invalid array length: %s", err))
			return nil
		}
		itemCount = int(l)
		hasCount = true
	} else {
		// If we don't have length, `op` must be the type tag of the length of the first key.
		d.off--
		d.scan.undo(op)
	}

	if hasCount {
		for ; itemCount > 0; itemCount-- {
			key, err := d.scanString()
			if err != nil {
				d.error(err)
				return nil
			}
			if hasType {
				m[key] = d.valueInterface(itemType)
			} else {
				m[key] = d.valueInterface(d.scanOnce())
			}
		}
	} else {
		for {
			// Look ahead for '}'.
			// TODO(imax): refactor so this isn't needed.
			op := d.scanOnce()
			if op == scanEndObject {
				break
			}
			d.off--
			d.scan.undo(op)

			key, err := d.scanString()
			if err != nil {
				d.error(err)
				return nil
			}
			m[key] = d.valueInterface(d.scanOnce())
		}
	}
	return m
}
