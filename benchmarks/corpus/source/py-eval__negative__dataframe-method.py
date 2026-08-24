import pandas as pd

frame = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
# DataFrame.eval is a pandas expression evaluator, not the Python builtin.
frame = frame.eval("c = a + b")
