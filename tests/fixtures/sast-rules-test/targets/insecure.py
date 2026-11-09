import sys


def run(expr):
    return eval(expr)


if __name__ == "__main__":
    print(run(sys.argv[1]))
