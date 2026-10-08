package netstack

import "gvisor.dev/gvisor/pkg/buffer"

func bufferFrom(b []byte) buffer.Buffer { return buffer.MakeWithData(append([]byte(nil), b...)) }
