/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <Python.h>

static PyObject *py_module = NULL;

enum {
  /* 00 */ PY_FUNC_CUSTOM_MUTATOR,
  /* 01 */ PY_FUNC_CUSTOM_CROSSOVER,
  PY_FUNC_COUNT
};

static PyObject *py_functions[PY_FUNC_COUNT];

static void LLVMFuzzerInitPythonModule() {
  Py_Initialize();
  char* module_name = getenv("LIBFUZZER_PYTHON_MODULE");

  if (module_name) {
    PyObject* py_name = PyUnicode_FromString(module_name);

    py_module = PyImport_Import(py_name);
    Py_DECREF(py_name);

    if (py_module != NULL) {
      py_functions[PY_FUNC_CUSTOM_MUTATOR] =
        PyObject_GetAttrString(py_module, "custom_mutator");
      py_functions[PY_FUNC_CUSTOM_CROSSOVER] =
        PyObject_GetAttrString(py_module, "custom_crossover");

      if (!py_functions[PY_FUNC_CUSTOM_MUTATOR]
        || !PyCallable_Check(py_functions[PY_FUNC_CUSTOM_MUTATOR])) {
        if (PyErr_Occurred())
          PyErr_Print();
        fprintf(stderr, "Error: Cannot find/call custom mutator function in"
                        " external Python module.\n");
        return;
      }

      if (!py_functions[PY_FUNC_CUSTOM_CROSSOVER]
        || !PyCallable_Check(py_functions[PY_FUNC_CUSTOM_CROSSOVER])) {
        if (PyErr_Occurred())
          PyErr_Print();
        fprintf(stderr, "Warning: Python module does not implement crossover"
                        " API, standard crossover will be used.\n");
        py_functions[PY_FUNC_CUSTOM_CROSSOVER] = NULL;
      }
    } else {
      if (PyErr_Occurred())
        PyErr_Print();
      fprintf(stderr, "Error: Failed to load external Python module \"%s\"\n",
      module_name);
    }
  } else {
    fprintf(stderr, "Warning: No Python module specified, please set the "
                    "LIBFUZZER_PYTHON_MODULE environment variable.\n");
    exit(1);
  }
}

static void LLVMFuzzerFinalizePythonModule() {
  if (py_module != NULL) {
    uint32_t i;
    for (i = 0; i < PY_FUNC_COUNT; ++i)
      Py_XDECREF(py_functions[i]);
    Py_DECREF(py_module);
  }
  Py_Finalize();
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  if (!py_module) {
    LLVMFuzzerInitPythonModule();
  }

  PyObject* py_args = PyTuple_New(3);

  // Convert Data and Size to a ByteArray
  PyObject* py_value = PyByteArray_FromStringAndSize((const char*)Data, Size);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert buffer.\n");
    return 0;
  }
  PyTuple_SetItem(py_args, 0, py_value);

  // Convert MaxSize to a PyLong
  py_value = PyLong_FromSize_t(MaxSize);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert maximum size.\n");
    return 0;
  }
  PyTuple_SetItem(py_args, 1, py_value);

  // Convert Seed to a PyLong
  py_value = PyLong_FromUnsignedLong((unsigned long)Seed);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert seed.\n");
    return 0;
  }
  PyTuple_SetItem(py_args, 2, py_value);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_CUSTOM_MUTATOR], py_args);

  Py_DECREF(py_args);

  if (py_value != NULL) {
    ssize_t ReturnedSize = PyByteArray_Size(py_value);
    if (ReturnedSize > MaxSize) {
      fprintf(stderr, "Warning: Python module returned buffer that exceeds "
                      "the maximum size. Returning a truncated buffer.\n");
      ReturnedSize = MaxSize;
    }
    memcpy(Data, PyByteArray_AsString(py_value), ReturnedSize);
    Py_DECREF(py_value);
    return ReturnedSize;
  } else {
    if (PyErr_Occurred())
      PyErr_Print();
    fprintf(stderr, "Error: Call failed\n");
    return 0;
  }
}
