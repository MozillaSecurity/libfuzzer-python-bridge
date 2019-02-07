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
    random.seed(seed)

    try:
        uncompressed = bytearray(zlib.decompress(data))
        native_mutator(uncompressed, max_size)
        compressed = bytearray(zlib.compress(uncompressed))
    except zlib.error:
        compressed = bytearray(zlib.compress(bytes("Hi", "utf8")))

    if len(compressed) > max_size:
        return compressed[0:max_size]
    return compressed
