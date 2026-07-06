// Added by Dice15.

#pragma once

#include "seal/context.h"
#include "seal/plaintext.h"
#include "seal/util/defines.h"
#include <vector>
#ifdef SEAL_USE_MSGSL
#include "gsl/span"
#endif

namespace seal
{
    /**
    Provides functionality for direct coefficient encoding in BFV/BGV. Given polynomial modulus degree N, 
    CoeffEncoder maps an input vector (length <= N) directly to the first k coefficients of a plaintext polynomial in R_t = Z_t[X]/(X^N + 1); 
    remaining coefficients are zero-padded. No CRT factorization, permutation, or slot interpretation is performed.

    Unlike BatchEncoder (which enables SIMD element-wise products via CRT batching), 
    homomorphic addition here is still element-wise on encoded data, 
    but homomorphic multiplication becomes *negacyclic polynomial multiplication* (i.e., convolution modulo X^N + 1), not element-wise multiplication.

    @par Mathematical Background
    Encoding is the identity embedding: v = (v_0,...,v_{k-1})  ->  P(X) = ¥Ò_{i=0}^{k-1} v_i X^i  (mod t), with zero padding to degree N-1. 
    Signed inputs use centered representation: |v_i| <= floor(t/2); negative values stored as t + v_i. 
    Decoding inverts this mapping and recovers centered integers.

    @par Comparison with BatchEncoder
    - BatchEncoder: CRT-based slot view; mult = slot-wise.
    - CoeffEncoder: coefficient view; mult = ring convolution.

    @par Valid Parameters
    Requires:
    - scheme_type::bfv or scheme_type::bgv
    - qualifiers().using_batching == true (ensures compatible N, roots, etc.)
    - Input length <= N
    - For uint64_t input: each value < plain_modulus
    - For int64_t input: |value| <= floor(plain_modulus / 2)

    @see BatchEncoder for CRT-based SIMD batching.
    @see EncryptionParameters, EncryptionParameterQualifiers.
    */
    class CoeffEncoder
    {
    public:
        CoeffEncoder(const SEALContext& context);

        void encode(const std::vector<std::uint64_t>& values, Plaintext& destination) const;

        void encode(const std::vector<std::int64_t>& values, Plaintext& destination) const;
#ifdef SEAL_USE_MSGSL
        void encode(gsl::span<const std::uint64_t> values, Plaintext& destination) const;

        void encode(gsl::span<const std::int64_t> values, Plaintext& destination) const;
#endif
        void decode(
            const Plaintext& plain, std::vector<std::uint64_t>& destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const;

        void decode(
            const Plaintext& plain, std::vector<std::int64_t>& destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const;
#ifdef SEAL_USE_MSGSL
        void decode(
            const Plaintext& plain, gsl::span<std::uint64_t> destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const;

        void decode(
            const Plaintext& plain, gsl::span<std::int64_t> destination,
            MemoryPoolHandle pool = MemoryManager::GetPool()) const;
#endif
        SEAL_NODISCARD inline auto slot_count() const noexcept
        {
            return slots_;
        }

    protected:
        CoeffEncoder(const CoeffEncoder& copy) = delete;

        CoeffEncoder(CoeffEncoder&& source) = delete;

        CoeffEncoder& operator=(const CoeffEncoder& assign) = delete;

        CoeffEncoder& operator=(CoeffEncoder&& assign) = delete;

        MemoryPoolHandle pool_ = MemoryManager::GetPool();

        SEALContext context_;

        std::size_t slots_;
    };
} // namespace seal