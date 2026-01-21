from mathx import add, mul


def run() -> int:
    x = add(1, 2)
    y = mul(x, 3)
    return y


if __name__ == "__main__":
    print(run())
