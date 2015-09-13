// Copyright 2010 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ubjson

// JSON value parser state machine.
// Just about at the limit of what is reasonable to write by hand.
// Some parts are a bit tedious, but overall it nicely factors out the
// otherwise common code from the multiple scanning functions
// in this package (Compact, Indent, checkValid, nextValue, etc).
//
// This file starts with two simple examples using the scanner
// before diving into the scanner itself.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/golang/glog"
)

// checkValid verifies that data is valid JSON-encoded data.
// scan is passed in for use by checkValid to avoid an allocation.
func checkValid(data []byte, scan *scanner) error {
	scan.reset()
	for _, c := range data {
		scan.bytes++
		v := scan.step(scan, int(c))
		glog.Infof("%#v -> %s", string([]byte{c}), scanToName[v])
		if v == scanError {
			return scan.err
		}
	}
	if scan.eof() == scanError {
		return scan.err
	}
	return nil
}

// nextValue splits data after the next whole JSON value,
// returning that value and the bytes that follow it as separate slices.
// scan is passed in for use by nextValue to avoid an allocation.
func nextValue(data []byte, scan *scanner) (value, rest []byte, err error) {
	scan.reset()
	for i, c := range data {
		v := scan.step(scan, int(c))
		glog.V(2).Infof("%#v -> %s", string([]byte{c}), scanToName[v])
		if v >= scanEndObject {
			switch v {
			// probe the scanner with a space to determine whether we will
			// get scanEnd on the next character. Otherwise, if the next character
			// is not a space, scanEndTop allocates a needless error.
			case scanEndObject, scanEndArray:
				if len(scan.parseState) == 0 {
					return data[:i+1], data[i+1:], nil
				}
			case scanError:
				return nil, nil, scan.err
			case scanEnd:
				return data[0:i], data[i:], nil
			}
		}
	}
	if scan.eof() == scanError {
		return nil, nil, scan.err
	}
	return data, nil, nil
}

// A SyntaxError is a description of a JSON syntax error.
type SyntaxError struct {
	msg    string // description of error
	Offset int64  // error occurred after reading Offset bytes
}

func (e *SyntaxError) Error() string { return e.msg }

// A scanner is a JSON scanning state machine.
// Callers call scan.reset() and then pass bytes in one at a time
// by calling scan.step(&scan, c) for each byte.
// The return value, referred to as an opcode, tells the
// caller about significant parsing events like beginning
// and ending literals, objects, and arrays, so that the
// caller can follow along if it wishes.
// The return value scanEnd indicates that a single top-level
// JSON value has been completed, *before* the byte that
// just got passed in.  (The indication must be delayed in order
// to recognize the end of numbers: is 123 a whole value or
// the beginning of 12345e+6?).
type scanner struct {
	// The step is a func to be called to execute the next transition.
	// Also tried using an integer constant and a single func
	// with a switch, but using the func directly was 10% faster
	// on a 64-bit Mac Mini, and it's nicer to read.
	step func(*scanner, int) int

	// Reached end of top-level value.
	endTop bool

	// Stack of what we're in the middle of - array values, object keys, object values.
	parseState []parseStackFrame

	// Error that happened, if any.
	err error

	// 1-byte redo (see undo method)
	redo      bool
	redoCode  int
	redoState func(*scanner, int) int

	// total bytes consumed, updated by decoder.Decode
	bytes int64

	// Number of bytes left until the end of value.
	bytesLeft     int
	scanningBytes bool
	afterBytes    func(*scanner)

	lenBytes []byte
}

type parseStackFrame struct {
	container int
	valueType byte
	itemsLeft int
	hasCount  bool
}

var scanToName = map[int]string{
	scanContinue:      "continue",
	scanBeginLiteral:  "beginLiteral",
	scanBeginObject:   "beginObject",
	scanObjectKey:     "objectKey",
	scanObjectValue:   "objectValue",
	scanEndObject:     "endObject",
	scanBeginArray:    "beginArray",
	scanArrayValue:    "arrayValue",
	scanEndArray:      "endArray",
	scanSkipSpace:     "skipSpace",
	scanEnd:           "end",
	scanError:         "error",
	scanNull:          "null",
	scanTrue:          "true",
	scanFalse:         "false",
	scanInt8:          "int8",
	scanUint8:         "uint8",
	scanInt16:         "int16",
	scanInt32:         "int32",
	scanInt64:         "int64",
	scanBignum:        "bignum",
	scanString:        "string",
	scanFloat64:       "float64",
	scanFloat32:       "float32",
	scanChar:          "char",
	scanPayload:       "payload",
	scanEndPayload:    "endPayload",
	scanContainerType: "containerType",
	scanContainerLen:  "containerLen",
}

// These values are returned by the state transition functions
// assigned to scanner.state and the method scanner.eof.
// They give details about the current state of the scan that
// callers might be interested to know about.
// It is okay to ignore the return value of any particular
// call to scanner.state: if one call returns scanError,
// every subsequent call will return scanError too.
// TODO(imax): prune unused values.
const (
	// Continue.
	scanContinue     = iota // uninteresting byte
	scanBeginLiteral        // end implied by next result != scanContinue
	scanBeginObject         // begin object
	scanObjectKey           // just finished object key (string)
	scanObjectValue         // just finished non-last object value
	scanEndObject           // end object (implies scanObjectValue if possible)
	scanBeginArray          // begin array
	scanArrayValue          // just finished array value
	scanEndArray            // end array (implies scanArrayValue if possible)
	scanSkipSpace           // space byte; can skip; known to be last "continue" result

	scanNull
	scanTrue
	scanFalse
	scanInt8
	scanUint8
	scanInt16
	scanInt32
	scanInt64
	scanBignum
	scanString
	scanFloat64
	scanFloat32
	scanChar
	scanPayload
	scanEndPayload
	scanContainerType
	scanContainerLen

	// Stop.
	scanEnd   // top-level value ended *before* this byte; known to be first "stop" result
	scanError // hit an error, scanner.err.
)

// These values are stored in the parseState stack.
// They give the current state of a composite value
// being scanned.  If the parser is inside a nested value
// the parseState describes the nested state, outermost at entry 0.
const (
	parseObjectKey   = iota // parsing object key (before colon)
	parseObjectValue        // parsing object value (after colon)
	parseArrayValue         // parsing array value
	parseObject
)

func scanTypeFromByte(c byte) (int, error) {
	switch c {
	case 'Z':
		return scanNull, nil
	case 'T':
		return scanTrue, nil
	case 'F':
		return scanFalse, nil
	case 'i':
		return scanInt8, nil
	case 'U':
		return scanUint8, nil
	case 'I':
		return scanInt16, nil
	case 'l':
		return scanInt32, nil
	case 'L':
		return scanInt64, nil
	case 'd':
		return scanFloat32, nil
	case 'D':
		return scanFloat64, nil
	case 'H':
		return scanBignum, nil
	case 'C':
		return scanChar, nil
	case 'S':
		return scanString, nil
	case '[':
		return scanBeginArray, nil
	case '{':
		return scanBeginObject, nil
	default:
		return -1, fmt.Errorf("unknown type tag: %#v", string([]byte{c}))
	}
}

// reset prepares the scanner for use.
// It must be called before calling s.step.
func (s *scanner) reset() {
	s.step = stateBeginValue
	s.parseState = s.parseState[0:0]
	s.err = nil
	s.redo = false
	s.endTop = false
	// TODO(imax): update undo/redo().
	s.bytesLeft = 0
	s.scanningBytes = false
}

// eof tells the scanner that the end of input has been reached.
// It returns a scan status just as s.step does.
func (s *scanner) eof() int {
	if s.err != nil {
		return scanError
	}
	if s.endTop {
		return scanEnd
	}
	if s.err == nil {
		s.err = &SyntaxError{"unexpected end of JSON input", s.bytes}
	}
	return scanError
}

// pushParseState pushes a new parse state p onto the parse stack.
func (s *scanner) pushParseState(p int) {
	s.parseState = append(s.parseState, parseStackFrame{container: p})
}

// popParseState pops a parse state (already obtained) off the stack
// and updates s.step accordingly.
func (s *scanner) popParseState() {
	n := len(s.parseState) - 1
	s.parseState = s.parseState[0:n]
	s.redo = false
	if n == 0 {
		s.step = stateEndTop
		s.endTop = true
	} else {
		s.step = stateEndValue
	}
}

func endValue(s *scanner) {
	s.step = stateEndValue
	if len(s.parseState) == 0 {
		// We're done with scanning one top-level value.
		s.endTop = true
		s.step = stateEndTop
	}
	for len(s.parseState) > 0 {
		ps := s.parseState[len(s.parseState)-1]
		if !ps.hasCount || ps.itemsLeft > 0 {
			break
		}
		s.popParseState()
	}
}

func isSpace(c rune) bool {
	return c == 'N'
}

func isType(c rune) bool {
	switch c {
	case 'Z', 'T', 'F', 'i', 'U', 'I', 'l', 'L', 'd', 'D', 'H', 'C', 'S', '[', '{':
		return true
	default:
		return false
	}
}

// stateBeginValue is the state at the beginning of the input.
func stateBeginValue(s *scanner, c int) int {
	if isSpace(rune(c)) {
		return scanSkipSpace
	}
	switch c {
	case '{':
		s.step = stateBeginObject
		s.pushParseState(parseObject)
		return scanBeginObject
	case '[':
		s.step = stateBeginArray
		s.pushParseState(parseArrayValue)
		return scanBeginArray
	case 'S':
		s.step = stateWantStringLen
		return scanString
	case 'T':
		endValue(s)
		return scanTrue
	case 'F':
		endValue(s)
		return scanFalse
	case 'Z':
		endValue(s)
		return scanNull
	case 'i':
		s.step = stateScanBytes
		s.scanningBytes = true
		s.bytesLeft = 1
		s.afterBytes = endValue
		return scanInt8
	case 'U':
		s.step = stateScanBytes
		s.scanningBytes = true
		s.bytesLeft = 1
		s.afterBytes = endValue
		return scanUint8
	case 'I':
		s.step = stateScanBytes
		s.scanningBytes = true
		s.bytesLeft = 2
		s.afterBytes = endValue
		return scanInt16
	case 'l':
		s.step = stateScanBytes
		s.scanningBytes = true
		s.bytesLeft = 4
		s.afterBytes = endValue
		return scanInt32
	case 'L':
		s.step = stateScanBytes
		s.scanningBytes = true
		s.bytesLeft = 8
		s.afterBytes = endValue
		return scanInt64
	case 'd':
		s.step = stateScanBytes
		s.scanningBytes = true
		s.bytesLeft = 4
		s.afterBytes = endValue
		return scanFloat32
	case 'D':
		s.step = stateScanBytes
		s.scanningBytes = true
		s.bytesLeft = 8
		s.afterBytes = endValue
		return scanFloat64
	case 'H':
		// TODO(imax): parse as uint64 or big number.
		s.step = stateWantStringLen
		return scanBignum
	case 'C':
		s.step = stateScanBytes
		s.scanningBytes = true
		s.bytesLeft = 1
		s.afterBytes = endValue
		return scanChar
	}
	return s.error(c, "looking for beginning of value")
}

// stateEndValue is the state after completing a value,
// such as after reading `{}` or `true` or `["x"`.
func stateEndValue(s *scanner, c int) int {
	n := len(s.parseState)
	if n == 0 {
		// Completed top-level before the current byte.
		s.step = stateEndTop
		s.endTop = true
		return stateEndTop(s, c)
	}
	ps := s.parseState[n-1]
	switch ps.container {
	case parseObject:
		switch {
		case ps.hasCount:
			if ps.itemsLeft <= 0 {
				s.popParseState()
				return scanEndObject
			}
		case c == '}':
			s.popParseState()
			return scanEndObject
		}
		return stateObjectKey(s, c)
	case parseArrayValue:
		switch {
		case ps.valueType != 0: // typed array (count is mandatory)
			if ps.itemsLeft > 0 {
				return stateTypedArrayItems(s, c)
			}
			s.popParseState()
			return scanEndArray
		case ps.valueType == 0 && ps.hasCount: // untyped array with count
			if ps.itemsLeft > 0 {
				return stateCountedArrayItems(s, c)
			}
			s.popParseState()
			return scanEndArray
		case c == ']':
			s.popParseState()
			return scanEndArray
		}
		return stateBeginValue(s, c)
	}
	return s.error(c, "")
}

// stateEndTop is the state after finishing the top-level value,
// such as after reading `{}` or `[1,2,3]`.
// Only space characters should be seen now.
func stateEndTop(s *scanner, c int) int {
	if c != 'N' {
		// Complain about non-space byte on next call.
		s.error(c, "after top-level value")
	}
	return scanEnd
}

func stateWantStringLen(s *scanner, c int) int {
	var r int
	switch c {
	case 'i':
		s.bytesLeft = 1
		r = scanInt8
	case 'U':
		s.bytesLeft = 1
		r = scanUint8
	case 'I':
		s.bytesLeft = 2
		r = scanInt16
	case 'l':
		s.bytesLeft = 4
		r = scanInt32
	case 'L':
		s.bytesLeft = 8
		r = scanInt64
	default:
		return s.error(c, "when expecting integer length")
	}
	s.step = stateStringLen
	s.scanningBytes = true
	s.lenBytes = make([]byte, 0, s.bytesLeft+1)
	s.lenBytes = append(s.lenBytes, byte(c))
	return r
}

func stateStringLen(s *scanner, c int) int {
	s.bytesLeft--
	s.lenBytes = append(s.lenBytes, byte(c))
	if s.bytesLeft <= 0 {
		switch s.lenBytes[0] {
		case 'i':
			s.bytesLeft = int(s.lenBytes[1])
		case 'U':
			s.bytesLeft = int(s.lenBytes[1])
		case 'I':
			var v int16
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.bytesLeft = int(v)
		case 'l':
			var v int32
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.bytesLeft = int(v)
		case 'L':
			var v int64
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.bytesLeft = int(v)
		default:
			return s.error(c, "invalid len type")
		}
		s.step = stateScanBytes
		s.afterBytes = endValue
		if s.bytesLeft == 0 {
			// Shortcut for zero-length values.
			s.scanningBytes = false
			s.step = stateEndValue
		}
		return scanEndPayload
	}
	return scanContinue
}

/*
// stateNeg is the state after reading `-` during a number.
func stateNeg(s *scanner, c int) int {
	if c == '0' {
		s.step = state0
		return scanContinue
	}
	if '1' <= c && c <= '9' {
		s.step = state1
		return scanContinue
	}
	return s.error(c, "in numeric literal")
}

// state1 is the state after reading a non-zero integer during a number,
// such as after reading `1` or `100` but not `0`.
func state1(s *scanner, c int) int {
	if '0' <= c && c <= '9' {
		s.step = state1
		return scanContinue
	}
	return state0(s, c)
}

// state0 is the state after reading `0` during a number.
func state0(s *scanner, c int) int {
	if c == '.' {
		s.step = stateDot
		return scanContinue
	}
	if c == 'e' || c == 'E' {
		s.step = stateE
		return scanContinue
	}
	return stateEndValue(s, c)
}

// stateDot is the state after reading the integer and decimal point in a number,
// such as after reading `1.`.
func stateDot(s *scanner, c int) int {
	if '0' <= c && c <= '9' {
		s.step = stateDot0
		return scanContinue
	}
	return s.error(c, "after decimal point in numeric literal")
}

// stateDot0 is the state after reading the integer, decimal point, and subsequent
// digits of a number, such as after reading `3.14`.
func stateDot0(s *scanner, c int) int {
	if '0' <= c && c <= '9' {
		s.step = stateDot0
		return scanContinue
	}
	if c == 'e' || c == 'E' {
		s.step = stateE
		return scanContinue
	}
	return stateEndValue(s, c)
}

// stateE is the state after reading the mantissa and e in a number,
// such as after reading `314e` or `0.314e`.
func stateE(s *scanner, c int) int {
	if c == '+' {
		s.step = stateESign
		return scanContinue
	}
	if c == '-' {
		s.step = stateESign
		return scanContinue
	}
	return stateESign(s, c)
}

// stateESign is the state after reading the mantissa, e, and sign in a number,
// such as after reading `314e-` or `0.314e+`.
func stateESign(s *scanner, c int) int {
	if '0' <= c && c <= '9' {
		s.step = stateE0
		return scanContinue
	}
	return s.error(c, "in exponent of numeric literal")
}

// stateE0 is the state after reading the mantissa, e, optional sign,
// and at least one digit of the exponent in a number,
// such as after reading `314e-2` or `0.314e+1` or `3.14e0`.
func stateE0(s *scanner, c int) int {
	if '0' <= c && c <= '9' {
		s.step = stateE0
		return scanContinue
	}
	return stateEndValue(s, c)
}
*/

func stateScanBytes(s *scanner, c int) int {
	s.bytesLeft--
	if s.bytesLeft <= 0 {
		s.scanningBytes = false
		s.afterBytes(s)
		s.afterBytes = nil
		return scanEndPayload
	}
	return scanContinue
}

func stateBeginArray(s *scanner, c int) int {
	switch c {
	case '$':
		s.step = stateArrayType
		s.parseState[len(s.parseState)-1].hasCount = true
		return scanContainerType
	case '#':
		s.step = stateArrayLen
		s.parseState[len(s.parseState)-1].hasCount = true
		return scanContainerLen
	default:
		return stateBeginValue(s, c)
	}
}

func stateArrayType(s *scanner, c int) int {
	switch {
	case isType(rune(c)):
		s.parseState[len(s.parseState)-1].valueType = byte(c)
		s.step = stateArrayHashAfterType
		return scanEndPayload
	default:
		return s.error(c, "expected type tag")
	}
}

func stateArrayHashAfterType(s *scanner, c int) int {
	switch c {
	case '#':
		s.step = stateArrayLenAfterType
		return scanContainerLen
	default:
		return s.error(c, "expected #")
	}
}

func stateArrayLenAfterType(s *scanner, c int) int {
	var r int
	switch c {
	case 'i':
		s.bytesLeft = 1
		r = scanInt8
	case 'U':
		s.bytesLeft = 1
		r = scanUint8
	case 'I':
		s.bytesLeft = 2
		r = scanInt16
	case 'l':
		s.bytesLeft = 4
		r = scanInt32
	case 'L':
		s.bytesLeft = 8
		r = scanInt64
	default:
		return s.error(c, "when expecting integer length")
	}
	s.step = stateArrayLenBytesAfterType
	s.scanningBytes = true
	s.lenBytes = make([]byte, 0, s.bytesLeft+1)
	s.lenBytes = append(s.lenBytes, byte(c))
	return r
}

func stateArrayLenBytesAfterType(s *scanner, c int) int {
	s.bytesLeft--
	s.lenBytes = append(s.lenBytes, byte(c))
	if s.bytesLeft <= 0 {
		s.scanningBytes = false
		switch s.lenBytes[0] {
		case 'i':
			s.parseState[len(s.parseState)-1].itemsLeft = int(s.lenBytes[1])
		case 'U':
			s.parseState[len(s.parseState)-1].itemsLeft = int(s.lenBytes[1])
		case 'I':
			var v int16
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		case 'l':
			var v int32
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		case 'L':
			var v int64
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		default:
			return s.error(c, "invalid len type")
		}
		s.step = stateTypedArrayItems
		return scanEndPayload
	}
	return scanContinue
}

func stateTypedArrayItems(s *scanner, c int) int {
	s.parseState[len(s.parseState)-1].itemsLeft--
	stateBeginValue(s, int(s.parseState[len(s.parseState)-1].valueType))
	return s.step(s, c)
}

func stateArrayLen(s *scanner, c int) int {
	var r int
	switch c {
	case 'i':
		s.bytesLeft = 1
		r = scanInt8
	case 'U':
		s.bytesLeft = 1
		r = scanUint8
	case 'I':
		s.bytesLeft = 2
		r = scanInt16
	case 'l':
		s.bytesLeft = 4
		r = scanInt32
	case 'L':
		s.bytesLeft = 8
		r = scanInt64
	default:
		return s.error(c, "when expecting integer length")
	}
	s.step = stateArrayLenBytes
	s.scanningBytes = true
	s.lenBytes = make([]byte, 0, s.bytesLeft+1)
	s.lenBytes = append(s.lenBytes, byte(c))
	return r
}

func stateArrayLenBytes(s *scanner, c int) int {
	s.bytesLeft--
	s.lenBytes = append(s.lenBytes, byte(c))
	if s.bytesLeft <= 0 {
		s.scanningBytes = false
		switch s.lenBytes[0] {
		case 'i':
			s.parseState[len(s.parseState)-1].itemsLeft = int(s.lenBytes[1])
		case 'U':
			s.parseState[len(s.parseState)-1].itemsLeft = int(s.lenBytes[1])
		case 'I':
			var v int16
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		case 'l':
			var v int32
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		case 'L':
			var v int64
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		default:
			return s.error(c, "invalid len type")
		}
		s.step = stateCountedArrayItems
		return scanEndPayload
	}
	return scanContinue
}

func stateCountedArrayItems(s *scanner, c int) int {
	s.parseState[len(s.parseState)-1].itemsLeft--
	return stateBeginValue(s, c)
}

func stateBeginObject(s *scanner, c int) int {
	switch c {
	case '$':
		s.step = stateObjectType
		s.parseState[len(s.parseState)-1].hasCount = true
		return scanContainerType
	case '#':
		s.step = stateObjectLen
		s.parseState[len(s.parseState)-1].hasCount = true
		return scanContainerLen
	default:
		return stateObjectKey(s, c)
	}
}

func stateObjectType(s *scanner, c int) int {
	switch {
	case isType(rune(c)):
		s.parseState[len(s.parseState)-1].valueType = byte(c)
		s.step = stateObjectHashAfterType
		return scanEndPayload
	default:
		return s.error(c, "expected type tag")
	}
}

func stateObjectHashAfterType(s *scanner, c int) int {
	switch c {
	case '#':
		s.step = stateObjectLenAfterType
		return scanContainerLen
	default:
		return s.error(c, "expected #")
	}
}

func stateObjectLenAfterType(s *scanner, c int) int {
	var r int
	switch c {
	case 'i':
		s.bytesLeft = 1
		r = scanInt8
	case 'U':
		s.bytesLeft = 1
		r = scanUint8
	case 'I':
		s.bytesLeft = 2
		r = scanInt16
	case 'l':
		s.bytesLeft = 4
		r = scanInt32
	case 'L':
		s.bytesLeft = 8
		r = scanInt64
	default:
		return s.error(c, "when expecting integer length")
	}
	s.step = stateObjectLenBytesAfterType
	s.scanningBytes = true
	s.lenBytes = make([]byte, 0, s.bytesLeft+1)
	s.lenBytes = append(s.lenBytes, byte(c))
	return r
}

func stateObjectLenBytesAfterType(s *scanner, c int) int {
	s.bytesLeft--
	s.lenBytes = append(s.lenBytes, byte(c))
	if s.bytesLeft <= 0 {
		s.scanningBytes = false
		switch s.lenBytes[0] {
		case 'i':
			s.parseState[len(s.parseState)-1].itemsLeft = int(s.lenBytes[1])
		case 'U':
			s.parseState[len(s.parseState)-1].itemsLeft = int(s.lenBytes[1])
		case 'I':
			var v int16
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		case 'l':
			var v int32
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		case 'L':
			var v int64
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		default:
			return s.error(c, "invalid len type")
		}
		s.step = stateObjectKey
		return scanEndPayload
	}
	return scanContinue
}

func stateObjectLen(s *scanner, c int) int {
	var r int
	switch c {
	case 'i':
		s.bytesLeft = 1
		r = scanInt8
	case 'U':
		s.bytesLeft = 1
		r = scanUint8
	case 'I':
		s.bytesLeft = 2
		r = scanInt16
	case 'l':
		s.bytesLeft = 4
		r = scanInt32
	case 'L':
		s.bytesLeft = 8
		r = scanInt64
	default:
		return s.error(c, "when expecting integer length")
	}
	s.step = stateObjectLenBytes
	s.scanningBytes = true
	s.lenBytes = make([]byte, 0, s.bytesLeft+1)
	s.lenBytes = append(s.lenBytes, byte(c))
	return r
}

func stateObjectLenBytes(s *scanner, c int) int {
	s.bytesLeft--
	s.lenBytes = append(s.lenBytes, byte(c))
	if s.bytesLeft <= 0 {
		s.scanningBytes = false
		switch s.lenBytes[0] {
		case 'i':
			s.parseState[len(s.parseState)-1].itemsLeft = int(s.lenBytes[1])
		case 'U':
			s.parseState[len(s.parseState)-1].itemsLeft = int(s.lenBytes[1])
		case 'I':
			var v int16
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		case 'l':
			var v int32
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		case 'L':
			var v int64
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.parseState[len(s.parseState)-1].itemsLeft = int(v)
		default:
			return s.error(c, "invalid len type")
		}
		s.step = stateObjectKey
		return scanEndPayload
	}
	return scanContinue
}

func stateObjectKey(s *scanner, c int) int {
	s.parseState[len(s.parseState)-1].itemsLeft--
	var r int
	switch c {
	case 'i':
		s.bytesLeft = 1
		r = scanInt8
	case 'U':
		s.bytesLeft = 1
		r = scanUint8
	case 'I':
		s.bytesLeft = 2
		r = scanInt16
	case 'l':
		s.bytesLeft = 4
		r = scanInt32
	case 'L':
		s.bytesLeft = 8
		r = scanInt64
	default:
		return s.error(c, "when expecting integer length")
	}
	s.step = stateObjectKeyLen
	s.scanningBytes = true
	s.lenBytes = make([]byte, 0, s.bytesLeft+1)
	s.lenBytes = append(s.lenBytes, byte(c))
	return r
}

func stateObjectKeyLen(s *scanner, c int) int {
	s.bytesLeft--
	s.lenBytes = append(s.lenBytes, byte(c))
	if s.bytesLeft <= 0 {
		switch s.lenBytes[0] {
		case 'i':
			s.bytesLeft = int(s.lenBytes[1])
		case 'U':
			s.bytesLeft = int(s.lenBytes[1])
		case 'I':
			var v int16
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.bytesLeft = int(v)
		case 'l':
			var v int32
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.bytesLeft = int(v)
		case 'L':
			var v int64
			if err := binary.Read(bytes.NewBuffer(s.lenBytes[1:]), binary.BigEndian, &v); err != nil {
				return s.error(c, fmt.Sprintf("invalid length: %s", err))
			}
			s.bytesLeft = int(v)
		default:
			return s.error(c, "invalid len type")
		}
		s.step = stateObjectKeyName
		return scanEndPayload
	}
	return scanContinue
}

func stateObjectKeyName(s *scanner, c int) int {
	s.bytesLeft--
	if s.bytesLeft <= 0 {
		s.scanningBytes = false
		s.step = stateObjectValue
		return scanEndPayload
	}
	return scanContinue
}

func stateObjectValue(s *scanner, c int) int {
	if t := s.parseState[len(s.parseState)-1].valueType; t != 0 {
		stateBeginValue(s, int(t))
		return s.step(s, c)
	}
	return stateBeginValue(s, c)
}

// stateError is the state after reaching a syntax error,
// such as after reading `[1}` or `5.1.2`.
func stateError(s *scanner, c int) int {
	return scanError
}

// error records an error and switches to the error state.
func (s *scanner) error(c int, context string) int {
	s.step = stateError
	s.err = &SyntaxError{"invalid character " + quoteChar(c) + " " + context, s.bytes}
	return scanError
}

// quoteChar formats c as a quoted character literal
func quoteChar(c int) string {
	// special cases - different from quoted strings
	if c == '\'' {
		return `'\''`
	}
	if c == '"' {
		return `'"'`
	}

	// use quoted string with different quotation marks
	s := strconv.Quote(string(c))
	return "'" + s[1:len(s)-1] + "'"
}

// undo causes the scanner to return scanCode from the next state transition.
// This gives callers a simple 1-byte undo mechanism.
func (s *scanner) undo(scanCode int) {
	if s.redo {
		panic("json: invalid use of scanner")
	}
	s.redoCode = scanCode
	s.redoState = s.step
	s.step = stateRedo
	s.redo = true
}

// stateRedo helps implement the scanner's 1-byte undo.
func stateRedo(s *scanner, c int) int {
	s.redo = false
	s.step = s.redoState
	return s.redoCode
}
