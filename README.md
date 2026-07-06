# Microsoft SEAL-Bootstrapping 3.0

This project provides an implementation of CKKS bootstrapping based on Microsoft SEAL. </br>
The 3.0 version of BTS is implemented with the following techniques:
- Approximate modular reduction funtion using taylor polynomial
- **Meta bootstrapping**
- **Sparse secret encapsulation**

### Performance
| Set   | Test              | logN | h      | h̃  | logΔ | logQ<sub>0</sub> | logQ<sub>bts</sub> | logP | Precision            | Time(s) |
|-------|-------------------|------|--------|----|------|------------------|--------------------|------|----------------------|---------|
|  I    | BTS               | 16   | 43,690 | 32 | 33   | 45               | 864                | 60   | ≈2<sup>-21.102</sup> | 11.583  |
|  II   | Meta-BTS (2-Fold) | 16   | 43,690 | 32 | 51   | 63               | 864                | 60   | ≈2<sup>-35.655</sup> | 26.234  |
|  III  | Meta-BTS (3-Fold) | 16   | 43,690 | 32 | 68   | 81               | 864                | 60   | ≈2<sup>-50.415</sup> | 39.971  |

**For any inquiries or feedback, please use the GitHub Issues tab or contact us at:**
> **Email: [`java_script@kakao.com`](java_script@kakao.com)**

</br>

# Contents
- [`Implementation`](#1-implementation)
- [`Test environment`](#2-test-environment)
- [`Example Code`](#3-example-code)
- [`References`](#4-references)

</br>

# 1. Implementation

### 1) CKKSBootstrapper
- Implemented the core functions for bootstrapping.
- Source files:
  - [`CKKSBootstrapper.h`](/native/src/seal/bootstrapper.h)
  - [`CKKSBootstrapper.cpp`](/native/src/seal/bootstrapper.cpp)

### 2) RNS & Context (Modified SEAL code)
- Implemented fast base conversion from q to Q<sub>LL</sub>.
- Source files:
  - [`rns.h`](/native/src/seal/util/rns.h)
  - [`rns.cpp`](/native/src/seal/util/rns.cpp)
  - [`context.h`](/native/src/seal/context.h)
  - [`context.cpp`](/native/src/seal/context.cpp)
    
### 3) Keygenerator & RLWE (Modified SEAL code)
- Implemented sparse ternary polynomial generation with a specified Hamming weight.
- Source files:
  - [`keygenerator.h`](/native/src/seal/keygenerator.h)
  - [`keygenerator.cpp`](/native/src/seal/keygenerator.cpp)
  - [`rlwe.h`](/native/src/seal/util/rlwe.h)
  - [`rlwe.cpp`](/native/src/seal/util/rlwe.cpp)
 
</br>

# 2. Test Environment

### 1) Test Environment
- CPU: Intel Core i5-8500 @ 3.00GHz
- RAM: 32 GB
- OS: Windows 11 Pro (Version 24H2, Build 26100.4349)
- Architecture: 64-bit, x64-based processor
- Compiler: Microsoft Visual Studio (MSVC), C++17
- Build Configuration: Release

</br>

# 3. Example Code
### 1. test.cpp
```cpp
void make_parms(
	CKKSBootstrapper::CKKSParametersLiteral& ckks_parms,
	CKKSBootstrapper::BTSParametersLiteral& bts_parms,
	CKKSBootstrapper::MetaBTSParametersLiteral& meta_bts_parms)
{
    ckks_parms.log_N = 16;
    ckks_parms.log_Q = { 45, 18, 18, 34, 34 };
    ckks_parms.log_P = 60;
    ckks_parms.log_scale = 68;

    bts_parms.d_0 = 15;
    bts_parms.r = 6;
    bts_parms.ephemeral_HWT = 32;   // h̃: For sparse secret encapsulation
    bts_parms.log_scale = 54;

    meta_bts_parms.k = 3;   // 3-Fold Meta-BTS
    meta_bts_parms.log_scale = { 32, 18, 18 };
}

void example()
{
    // Parameters
	EncryptionParameters parms;
	CKKSBootstrapper::CKKSParametersLiteral ckks_parms;
    CKKSBootstrapper::BTSParametersLiteral bts_parms;
    CKKSBootstrapper::MetaBTSParametersLiteral meta_bts_parms;

    make_parms(ckks_parms, bts_parms, meta_bts_parms);    
	CKKSBootstrapper::create_encryption_parameters(ckks_parms, bts_parms, parms);


    // Context
    SEALContext context(parms, true, sec_level_type::none);


    // Keys
	KeyGenerator keygen(context);   // dense secret key generator.
	KeyGenerator keygen_tilde(context, bts_parms.ephemeral_HWT);   // sparse secret key generator.
    SecretKey secret_key;
    SecretKey secret_key_tilde;
    PublicKey public_key;
    KSwitchKeys kswitch_keys_sk_to_sk_tilde;
	KSwitchKeys kswitch_keys_sk_tilde_to_sk;
    RelinKeys relin_keys;
    GaloisKeys galois_keys;
    vector<int> rotate_steps;
   
    secret_key = keygen.secret_key();
	secret_key_tilde = keygen_tilde.secret_key();
    keygen.create_public_key(public_key);
    keygen_tilde.create_kswitch_keys(secret_key, kswitch_keys_sk_to_sk_tilde);   // kswitch key: dense -> sparse
    keygen.create_kswitch_keys(secret_key_tilde, kswitch_keys_sk_tilde_to_sk);   // kswitch key: sparse -> dense
    keygen.create_relin_keys(relin_keys);
    CKKSBootstrapper::create_rotation_steps(ckks_parms, rotate_steps);
    keygen.create_galois_keys(rotate_steps, galois_keys);


    // Algorithms
    CKKSEncoder encoder(context);
    CKKSBootstrapper bootstrapper(ckks_parms, bts_parms, context, encoder);
    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);


    // Random data (< 0)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<double> dist(0.0, 1.0);

    vector<complex<double_t>> vector_1, res_vector;
    vector_1.reserve(encoder.slot_count());
    for (size_t i = 0; i < encoder.slot_count(); i++)
    {
        vector_1.push_back({ static_cast<double_t>(dist(gen)) });
    }

    Plaintext plain_1, plain_res;
    encoder.encode(vector_1, pow(2, ckks_parms.log_scale), plain_1);

    Ciphertext cipher_1, cipher_res;
    encryptor.encrypt(plain_1, cipher_1);


    // BTS
    bootstrapper.bootstrapping(
		cipher_1, encoder, evaluator, kswitch_keys_sk_to_sk_tilde, kswitch_keys_sk_tilde_to_sk, relin_keys, galois_keys, cipher_res, false);
    while (cipher_res.coeff_modulus_size() > 1)
    {
        evaluator.mod_reduce_to_next_inplace(cipher_res);
    }


	// Meta-BTS
	bootstrapper.meta_bootstrapping(
		cipher_1, encoder, evaluator, kswitch_keys_sk_to_sk_tilde, kswitch_keys_sk_tilde_to_sk, relin_keys, galois_keys, cipher_res, false);
    while (cipher_res.coeff_modulus_size() > meta_bts_parms.k)
    {
        evaluator.mod_reduce_to_next_inplace(cipher_res);
    }
}
```

</br>

# 4. References

#### 1. Homomorphic Encryption for Arithmetic of Approximate Numbers
* https://eprint.iacr.org/2016/421.pdf

#### 2. A Full RNS Variant of Approximate Homomorphic Encryption
* https://eprint.iacr.org/2018/931.pdf

#### 3. Secure Outsourced Matrix Computation and Application to Neural Networks
* https://eprint.iacr.org/2018/1041.pdf

#### 4. Bootstrapping for Approximate Homomorphic Encryption
* https://eprint.iacr.org/2018/153.pdf

#### 5. Improved Bootstrapping for Approximate Homomorphic Encryption
* https://eprint.iacr.org/2018/1043.pdf

#### 6. Bootstrapping for approximate homomorphic encryption with negligible failure-probability by using sparse-secret encapsulation
* https://eprint.iacr.org/2022/024.pdf

#### 7. Meta-bts: Bootstrapping precision beyond the limit
* https://dl.acm.org/doi/pdf/10.1145/3548606.3560696
