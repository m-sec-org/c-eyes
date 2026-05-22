//go:build yarax && cgo && linux && static_link

package riskanalysis

/*
#cgo pkg-config: --static yara_x_capi
*/
import "C"
