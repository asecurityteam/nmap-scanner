// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/asecurityteam/nmap-scanner/pkg/domain (interfaces: Scanner)

// Package v1 is a generated GoMock package.
package v1

import (
	context "context"
	domain "github.com/asecurityteam/nmap-scanner/pkg/domain"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockScanner is a mock of Scanner interface
type MockScanner struct {
	ctrl     *gomock.Controller
	recorder *MockScannerMockRecorder
}

// MockScannerMockRecorder is the mock recorder for MockScanner
type MockScannerMockRecorder struct {
	mock *MockScanner
}

// NewMockScanner creates a new mock instance
func NewMockScanner(ctrl *gomock.Controller) *MockScanner {
	mock := &MockScanner{ctrl: ctrl}
	mock.recorder = &MockScannerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockScanner) EXPECT() *MockScannerMockRecorder {
	return m.recorder
}

// Scan mocks base method
func (m *MockScanner) Scan(arg0 context.Context, arg1 string) ([]domain.Finding, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Scan", arg0, arg1)
	ret0, _ := ret[0].([]domain.Finding)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Scan indicates an expected call of Scan
func (mr *MockScannerMockRecorder) Scan(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Scan", reflect.TypeOf((*MockScanner)(nil).Scan), arg0, arg1)
}
