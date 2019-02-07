/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <Python.h>

static void LLVMFuzzerFinalizePythonModule();
static void LLVMFuzzerInitPythonModule();

static PyObject* py_module = NULL;

class LLVMFuzzerPyContext {
  public:
    LLVMFuzzerPyContext() {
      if (!py_module) {
        LLVMFuzzerInitPythonModule();
      }
    }
    ~LLVMFuzzerPyContext() {
      if (py_module) {
        LLVMFuzzerFinalizePythonModule();
      }
    }
};

// This takes care of (de)initializing things properly
LLVMFuzzerPyContext init;

static void py_fatal_error() {
  fprintf(stderr, "The libFuzzer Python layer encountered a critical error.\n");
  fprintf(stderr, "Please fix the messages above and then restart fuzzing.\n");
  exit(1);
}

enum {
  /* 00 */ PY_FUNC_CUSTOM_MUTATOR,
  /* 01 */ PY_FUNC_CUSTOM_CROSSOVER,
  PY_FUNC_COUNT
};

static PyObject* py_functions[PY_FUNC_COUNT];

// Forward-declare the libFuzzer's mutator callback.
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

// This function unwraps the Python arguments passed, which must be
//
// 1) A bytearray containing the data to be mutated
// 2) An int containing the maximum size of the new mutation
//
// The function will modify the bytearray in-place (and resize it accordingly)
// if necessary. It returns None.
PyObject* LLVMFuzzerMutatePyCallback(PyObject* data, PyObject* args) {
  PyObject* py_value;

  // Get MaxSize first, so we know how much memory we need to allocate
  py_value = PyTuple_GetItem(args, 1);
  if (!py_value) {
    fprintf(stderr, "Error: Missing MaxSize argument to native callback.\n");
    py_fatal_error();
  }
  size_t MaxSize = PyLong_AsSize_t(py_value);
  if (MaxSize == (size_t)-1 && PyErr_Occurred()) {
    PyErr_Print();
    fprintf(stderr, "Error: Failed to convert MaxSize argument to size_t.\n");
    py_fatal_error();
  }

  // Now get the ByteArray with our data and resize it appropriately
  py_value = PyTuple_GetItem(args, 0);
  size_t Size = (size_t)PyByteArray_Size(py_value);
  if (PyByteArray_Resize(py_value, MaxSize) < 0) {
    fprintf(stderr, "Error: Failed to resize ByteArray to MaxSize.\n");
    py_fatal_error();
  }

  // Call libFuzzer's native mutator
  size_t RetLen =
    LLVMFuzzerMutate((uint8_t *)PyByteArray_AsString(py_value), Size, MaxSize);

  if (PyByteArray_Resize(py_value, RetLen) < 0) {
    fprintf(stderr, "Error: Failed to resize ByteArray to RetLen.\n");
    py_fatal_error();
  }

  Py_RETURN_NONE;
}

static PyMethodDef LLVMFuzzerMutatePyMethodDef = {
  "LLVMFuzzerMutate",
  LLVMFuzzerMutatePyCallback,
  METH_VARARGS | METH_STATIC,
  NULL
};

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
        py_fatal_error();
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
      py_fatal_error();
    }
  } else {
    fprintf(stderr, "Warning: No Python module specified, please set the "
                    "LIBFUZZER_PYTHON_MODULE environment variable.\n");
    py_fatal_error();
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
  PyObject* py_args = PyTuple_New(4);

  // Convert Data and Size to a ByteArray
  PyObject* py_value = PyByteArray_FromStringAndSize((const char*)Data, Size);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert buffer.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 0, py_value);

  // Convert MaxSize to a PyLong
  py_value = PyLong_FromSize_t(MaxSize);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert maximum size.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 1, py_value);

  // Convert Seed to a PyLong
  py_value = PyLong_FromUnsignedLong((unsigned long)Seed);
  if (!py_value) {
    Py_DECREF(py_args);
    fprintf(stderr, "Error: Failed to convert seed.\n");
    py_fatal_error();
  }
  PyTuple_SetItem(py_args, 2, py_value);

  PyObject* py_callback = PyCFunction_New(&LLVMFuzzerMutatePyMethodDef, NULL);
  if (!py_callback) {
    fprintf(stderr, "Failed to create native callback\n");
    py_fatal_error();
  }

  // Pass the native callback
  PyTuple_SetItem(py_args, 3, py_callback);

  py_value = PyObject_CallObject(py_functions[PY_FUNC_CUSTOM_MUTATOR], py_args);

  Py_DECREF(py_args);
  Py_DECREF(py_callback);

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
    py_fatal_error();
  }
  return 0;
}
