
#pragma once
#include <ethash/keccak.hpp>
#include "FixedHash.h"
#include "vector_ref.h"

namespace dev {

    /// Calculate SHA3-256 hash of the given input and load it into the given output.
    /// @returns false if o_output.size() != 32.
    bool sha3(bytesConstRef _input, bytesRef o_output) noexcept;

/// Calculate SHA3-256 hash of the given input, returning as a 256-bit hash.
    inline h256 sha3(bytesConstRef _input) noexcept {
        h256 ret;
        sha3(_input, ret.ref());
        return ret;
    }

/// Calculate SHA3-256 hash of the given input, returning as a 256-bit hash.
    inline h256 sha3(bytes const &_input) noexcept {
        return sha3(bytesConstRef(&_input));
    }
}