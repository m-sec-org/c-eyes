//go:build yarax && cgo && linux && !static_link

package riskanalysis

/*
#cgo pkg-config: yara_x_capi
*/
import "C"
