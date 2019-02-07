# libfuzzer-python-bridge
A Python3 bridge for implementing custom libFuzzer mutators

**Important:** This is proof-of-concept and work in progress. Expect the Python API to change.

## Building and Running the Examples

To build the examples:

    clang -o example_compressed_python -g example_compressed_python.cpp -fsanitize=fuzzer -lz -DCUSTOM_MUTATOR -I/usr/include/python3.6m -lpython3.6m
    clang -o example_compressed_native -g example_compressed_native.cpp -fsanitize=fuzzer -lz -DCUSTOM_MUTATOR


Python Build flags can be found using

    python3-config --cflags --ldflags

and the flags above should work for Ubuntu LTS (18.04).

You can build with `-DBENCHMARK` to leave out the crashing code in order to compare performance of the two implementations.

To run the python example, use

    PYTHONPATH=. LIBFUZZER_PYTHON_MODULE=pymodules.example_compressed ./example_compressed_python

## Using with your own targets

All you need to do on the C/C++ side is

    #include "python_bridge.cpp"

in the target file where you have `LLVMFuzzerTestOneInput` (or any other compilation unit that is linked to the target)
and then build with the Python include and linker flags added to your build configuration.

Then write a Python module that does what you would like the fuzzer to do, you might want to use
the `example_compressed` module found in the `pymodules/` folder as a basis. Then just run your
fuzzing as shown in the examples above.

## TODO

* Implement `LLVMFuzzerCustomCrossOver` in C++ and Python example
* For some reason, the Python code is faster in benchmarks than the C++ code. There must be a bug somewhere, please find it!
