#!/usr/bin/env python
# encoding: utf-8
'''
Example Python Module for LibFuzzer
@author:     Christian Holler (:decoder)
@license:
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at http://mozilla.org/MPL/2.0/.
@contact:    choller@mozilla.com
'''

import random
import sys
import zlib


def custom_mutator(data, max_size, seed, native_mutator):
    '''
    Called for each mutation.

    @type data: bytearray
    @param data: The data that should be mutated.

    @type max_size: int
    @param max_size: The maximum size of the returned data.

    @type seed: int
    @param seed: Seed for random decisions.

    @type native_mutator: function
    @param native_mutator: Callback to the native libFuzzer mutator.
                           This mutator expects a bytearray and the
                           max_size parameter. It modifies and resizes
                           the bytearray in-place and returns None.

    @rtype: bytearray
    @return: A new bytearray containing the mutated data.
    '''
    # If you want to make any random decisions within the mutator,
    # you must base them on the provided seed.
    random.seed(seed)

    try:
        uncompressed = bytearray(zlib.decompress(data))

        # This calls back into libFuzzer to let the builtin mutation routine
        # deal with the uncompressed bytes. Using the native mutator is not
        # mandatory, but recommended if you just want to mutate blobs of data.
        # The builtin native mutator uses data flow feedback from the trace-cmp
        # instrumentation, so it is superior to implementing your own simple
        # binary mutations.
        native_mutator(uncompressed, max_size)

        compressed = bytearray(zlib.compress(uncompressed))
    except zlib.error:
        compressed = bytearray(zlib.compress(bytes("Hi", "utf8")))

    # The bridge implementation will issue a warning if you return too much
    # data, so make sure to stay below max_size. Note that it is possible for
    # the initial data buffer to be larger than max_size already.
    if len(compressed) > max_size:
        return compressed[0:max_size]
    return compressed
