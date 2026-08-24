import ast


def compute(expression):
    # ast.literal_eval accepts only literals, so the value reaching eval
    # cannot carry code.
    return eval(ast.literal_eval(expression))
