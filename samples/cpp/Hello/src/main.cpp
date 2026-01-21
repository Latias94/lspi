#include <iostream>

#include "mathx.h"

int run() {
  int x = add(1, 2);
  int y = mul(x, 3);
  return y;
}

int main() {
  std::cout << run() << "\n";
  return 0;
}
