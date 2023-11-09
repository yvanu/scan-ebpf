package ebpf

import "github.com/asavie/xdp"

//go:generate $HOME/go/bin/bpf2go  -cc clang-10 portfilter port_filter.c -- -I /usr/include/ -I ./include   -nostdinc -O3

func NewPortFilter(port uint32) (*xdp.Program, error) {
	spec, err := loadPortfilter()
	if err != nil {
		return nil, err
	}

	if err := spec.RewriteConstants(map[string]interface{}{"PORT": uint64(port)}); err != nil {
		return nil, err
	}
	var program portfilterObjects
	err = spec.LoadAndAssign(&program, nil)
	if err != nil {
		return nil, err
	}
	p := &xdp.Program{Program: program.XdpSockProg, Queues: program.QidconfMap, Sockets: program.XsksMap}
	return p, err
}
