# libfuzzer-python-bridge
A Python3 bridge for implementing custom libFuzzer mutators

**Important:** This is proof-of-concept and work in progress. Expect the Python API to change.

## Building

To build the examples:

    clang -o example_compressed_python -g example_compressed_python.cpp -fsanitize=fuzzer -lz -DCUSTOM_MUTATOR -I/usr/include/python3.6m -lpython3.6m
    clang -o example_compressed_native -g example_compressed_native.cpp -fsanitize=fuzzer -lz -DCUSTOM_MUTATOR


Python Build flags can be found using

    python3-config --cflags --ldflags

and the flags above should work for Ubuntu LTS (18.04).

You can build with -DBENCHMARK to leave out the crashing code in order to compare performance of the two implementations.

## Running

To run the python example, use

    PYTHONPATH=. LIBFUZZER_PYTHON_MODULE=pymodules.example_compressed ./example_compressed_python

## TODO

* Support calling `LLVMFuzzerMutate` from Python (e.g. for the PNG example)
* `LLVMFuzzerFinalizePythonModule` currently isn't called
* `LLVMFuzzerInitPythonModule` should be called by a global constructor
