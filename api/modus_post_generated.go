// Code generated by Modus. DO NOT EDIT.

package main

import (
	"unsafe"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
	"time"
	"github.com/hypermodeinc/modus/sdk/go/pkg/http"
	"nfe-modus/api/functions/auth"
	"nfe-modus/api/functions/user"
)

var __pins = make(map[unsafe.Pointer]int)

//go:export __unpin
func __unpin(p unsafe.Pointer) {
	n := __pins[p]
	if n == 1 {
		delete(__pins, p)
	} else {
		__pins[p] = n - 1
	}
}

//go:export __new
func __new(id int) unsafe.Pointer {
	switch id {
	case 3:
		o := new(dgraph.Mutation)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 4:
		o := new(dgraph.Query)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 5:
		o := new(dgraph.Request)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 6:
		o := new(dgraph.Response)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 7:
		o := new(http.Header)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 8:
		o := new(http.Headers)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 9:
		o := new(http.Request)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 10:
		o := new(http.Response)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 11:
		o := new(auth.GenerateOTPRequest)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 12:
		o := new(auth.GenerateOTPResponse)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 13:
		o := new(auth.User)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 14:
		o := new(auth.VerifyOTPRequest)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 15:
		o := new(auth.VerifyOTPResponse)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 16:
		o := new(user.GetUserTimestampsInput)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 17:
		o := new(user.UserTimestamps)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 18:
		o := new(string)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 19:
		o := new([]*dgraph.Mutation)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 20:
		o := new([]*http.Header)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 21:
		o := new([]string)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 22:
		o := new(dgraph.Mutation)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 23:
		o := new(dgraph.Query)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 24:
		o := new(dgraph.Request)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 25:
		o := new(dgraph.Response)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 26:
		o := new(http.Header)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 27:
		o := new(http.Headers)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 28:
		o := new(http.Request)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 29:
		o := new(http.Response)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 30:
		o := new(map[string]*http.Header)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 31:
		o := new(map[string]string)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 32:
		o := new(auth.GenerateOTPRequest)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 33:
		o := new(auth.GenerateOTPResponse)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 34:
		o := new(auth.User)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 35:
		o := new(auth.VerifyOTPRequest)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 36:
		o := new(auth.VerifyOTPResponse)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 37:
		o := new(user.GetUserTimestampsInput)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 38:
		o := new(user.UserTimestamps)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	case 39:
		o := new(time.Time)
		p := unsafe.Pointer(o)
		__pins[p]++
		return p
	}

	return nil
}

//go:export __make
func __make(id, size int) unsafe.Pointer {
	switch id {
	case 1:
		o := make([]byte, size)
		p := unsafe.Pointer(&o)
		__pins[p]++
		return p
	case 2:
		o := string(make([]byte, size))
		p := unsafe.Pointer(&o)
		__pins[p]++
		return p
	case 19:
		o := make([]*dgraph.Mutation, size)
		p := unsafe.Pointer(&o)
		__pins[p]++
		return p
	case 20:
		o := make([]*http.Header, size)
		p := unsafe.Pointer(&o)
		__pins[p]++
		return p
	case 21:
		o := make([]string, size)
		p := unsafe.Pointer(&o)
		__pins[p]++
		return p
	case 30:
		o := make(map[string]*http.Header, size)
		p := unsafe.Pointer(&o)
		__pins[p]++
		return p
	case 31:
		o := make(map[string]string, size)
		p := unsafe.Pointer(&o)
		__pins[p]++
		return p
	}

	return nil
}

//go:export __read_map
func __read_map(id int, m unsafe.Pointer) uint64 {
	switch id {
	case 30:
		return __doReadMap(*(*map[string]*http.Header)(m))
	case 31:
		return __doReadMap(*(*map[string]string)(m))
	}

	return 0
}

func __doReadMap[M ~map[K]V, K comparable, V any](m M) uint64 {
	size := len(m)
	keys := make([]K, size)
	values := make([]V, size)
	
	i := 0
	for k, v := range m {
		keys[i] = k
		values[i] = v
		i++
	}

	pKeys := uint32(uintptr(unsafe.Pointer(&keys)))
	pValues := uint32(uintptr(unsafe.Pointer(&values)))
	return uint64(pKeys)<<32 | uint64(pValues)
}

//go:export __write_map
func __write_map(id int, m, keys, values unsafe.Pointer) {
	switch id {
	case 30:
		__doWriteMap(*(*map[string]*http.Header)(m), *(*[]string)(keys), *(*[]*http.Header)(values))
	case 31:
		__doWriteMap(*(*map[string]string)(m), *(*[]string)(keys), *(*[]string)(values))
	}
}

func __doWriteMap[M ~map[K]V, K comparable, V any](m M, keys[]K, values[]V) {
	for i := 0; i < len(keys); i++ {
		m[keys[i]] = values[i]
	}
}
