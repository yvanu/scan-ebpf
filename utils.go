package scan

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
)

func getGatewayMac() net.HardwareAddr {
	routeList, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		panic(err)
	}
	var defaultRoute *netlink.Route
	for _, route := range routeList {
		route := route
		if route.Gw != nil && route.Dst == nil {
			defaultRoute = &route
		}
	}
	if defaultRoute == nil {
		panic("找不到默认路由")
	}

	neighborList, err := netlink.NeighList(defaultRoute.LinkIndex, netlink.FAMILY_V4)
	if err != nil {
		panic(err)
	}

	fmt.Println("defaultRoute", defaultRoute)
	var gatewayMAC net.HardwareAddr
	for _, neighbor := range neighborList {
		if neighbor.IP.String() == defaultRoute.Gw.String() {
			gatewayMAC = neighbor.HardwareAddr
			break
		}
	}
	if gatewayMAC == nil {
		panic("网关mac为空")
	}
	return gatewayMAC
}
