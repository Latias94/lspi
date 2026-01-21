package main

import (
	"fmt"

	"example.com/lspi-go-hello/mathx"
)

func main() {
	fmt.Println(run())
}

func run() int {
	x := mathx.Add(1, 2)
	y := mathx.Mul(x, 3)
	return y
}
