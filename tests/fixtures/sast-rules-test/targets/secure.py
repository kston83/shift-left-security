import ast
import sys


def run(expr):
    return ast.literal_eval(expr)


if __name__ == "__main__":
    print(run(sys.argv[1]))
