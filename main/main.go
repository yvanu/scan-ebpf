package main

import (
	"fmt"
	"github.com/asavie/xdp/examples/scan"
	"time"
)

func main() {
	stime := time.Now()
	scanner := scan.NewScanner("ens33", 0)
	srcPort := 12342
	go scanner.Receive("192.168.0.111", srcPort)
	scanner.Send("192.168.0.111", "43.159.%d.%d", srcPort, 9898)

	//scanner.Send("192.168.0.111", fmt.Sprintf("120.232.21.%d", 54), 12345, 80)
	//scanner.Send("192.168.0.111", fmt.Sprintf("43.159.149.32"), 12345, 9898)
	fmt.Println(time.Now().Sub(stime))
	for {
	}

}
