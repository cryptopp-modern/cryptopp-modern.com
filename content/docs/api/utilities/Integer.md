---
title: Integer
description: Arbitrary precision integer class for big number operations
weight: 12
---

**Header:** `#include <cryptopp/integer.h>` | **Namespace:** `CryptoPP`
**Since:** Crypto++ 1.0
**Thread Safety:** Thread-safe for read operations; not thread-safe for modification

The `Integer` class provides arbitrary precision integer arithmetic for cryptographic operations. It's used internally for RSA, DSA, Diffie-Hellman, and other public-key algorithms, but can also be used directly for big number computations.

## Quick Example

```cpp
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <iostream>

using namespace CryptoPP;

// Create integers
Integer a("12345678901234567890");
Integer b(1000);
Integer c = a + b;

std::cout << "a = " << a << std::endl;
std::cout << "b = " << b << std::endl;
std::cout << "a + b = " << c << std::endl;

// Random prime generation
AutoSeededRandomPool rng;
Integer prime = MaurerProvablePrime(rng, 512);  // 512-bit prime
std::cout << "Prime: " << prime << std::endl;
```

## Usage Guidelines

{{< callout type="info" title="Do" >}}
- Use for RSA key generation and operations
- Use for Diffie-Hellman parameters
- Use modular arithmetic functions for cryptographic operations
- Use `SecBlock<word>` for sensitive values that need secure memory
{{< /callout >}}

{{< callout type="warning" title="Avoid" >}}
- Don't use for performance-critical non-crypto math (use GMP instead)
- Don't ignore timing side-channels in custom crypto code
- Don't use `Integer` alone for secure random number generation
{{< /callout >}}

## Constructors

```cpp
// Default (zero)
Integer();

// From signed/unsigned integers
Integer(signed long value);
Integer(unsigned long value);
Integer(word value);

// From string (decimal, hex, octal)
Integer(const char* str);
Integer(const std::string& str);

// From byte array (big-endian)
Integer(const byte* encodedInteger, size_t byteCount,
        Signedness sign = UNSIGNED);

// Random integer
Integer(RandomNumberGenerator& rng, size_t bitCount);

// Random integer in range
Integer(RandomNumberGenerator& rng,
        const Integer& min, const Integer& max);

// Copy constructor
Integer(const Integer& other);
```

### String Format

```cpp
// Decimal (default)
Integer a("12345678901234567890");

// Hexadecimal (prefix with 0x)
Integer b("0xDEADBEEF");

// Octal (prefix with 0)
Integer c("0777");

// Negative
Integer d("-12345");
```

## Constants

```cpp
Integer::Zero()   // Returns 0
Integer::One()    // Returns 1
Integer::Two()    // Returns 2
```

## Arithmetic Operators

```cpp
Integer a(100), b(7);

Integer sum = a + b;        // Addition
Integer diff = a - b;       // Subtraction
Integer prod = a * b;       // Multiplication
Integer quot = a / b;       // Division
Integer rem = a % b;        // Modulo

a += b;                     // In-place addition
a -= b;                     // In-place subtraction
a *= b;                     // In-place multiplication
a /= b;                     // In-place division
a %= b;                     // In-place modulo

Integer neg = -a;           // Negation
++a;                        // Increment
--a;                        // Decrement
```

## Comparison Operators

```cpp
Integer a(100), b(200);

bool eq = (a == b);         // Equal
bool ne = (a != b);         // Not equal
bool lt = (a < b);          // Less than
bool le = (a <= b);         // Less or equal
bool gt = (a > b);          // Greater than
bool ge = (a >= b);         // Greater or equal

int cmp = a.Compare(b);     // Returns -1, 0, or 1
```

## Bitwise Operations

```cpp
Integer a("0xFF00"), b("0x0F0F");

Integer andResult = a & b;   // Bitwise AND
Integer orResult = a | b;    // Bitwise OR
Integer xorResult = a ^ b;   // Bitwise XOR

Integer shifted = a << 4;    // Left shift
Integer rshifted = a >> 4;   // Right shift

a &= b;                      // In-place AND
a |= b;                      // In-place OR
a ^= b;                      // In-place XOR
a <<= 4;                     // In-place left shift
a >>= 4;                     // In-place right shift
```

## Key Methods

### BitCount / ByteCount

```cpp
unsigned int BitCount() const;   // Number of significant bits
unsigned int ByteCount() const;  // Number of bytes needed
```

### IsZero / IsNegative / IsPositive

```cpp
bool IsZero() const;
bool IsNegative() const;
bool IsPositive() const;
bool IsOdd() const;
bool IsEven() const;
```

### GetBit / SetBit

```cpp
bool GetBit(size_t i) const;     // Get bit at position i
void SetBit(size_t i, bool value = true);
```

### Encode / Decode

```cpp
// Encode to byte array (big-endian)
void Encode(byte* output, size_t outputLen) const;

// Encode minimum bytes
void Encode(BufferedTransformation& bt, size_t outputLen) const;

// Decode from byte array
void Decode(const byte* input, size_t inputLen, Signedness sign = UNSIGNED);
```

## Modular Arithmetic

### a_times_b_mod_c

```cpp
Integer a_times_b_mod_c(const Integer& a, const Integer& b, const Integer& c);
```

Computes (a × b) mod c efficiently.

### a_exp_b_mod_c

```cpp
Integer a_exp_b_mod_c(const Integer& a, const Integer& b, const Integer& c);
```

Computes a^b mod c (modular exponentiation).

### InverseMod

```cpp
Integer InverseMod(const Integer& n) const;
```

Computes modular multiplicative inverse.

### ModularExponentiation

```cpp
Integer ModularExponentiation(const Integer& e, const Integer& m) const;
```

Computes this^e mod m.

## Complete Examples

### Example 1: Basic Arithmetic

```cpp
#include <cryptopp/integer.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    Integer a("12345678901234567890");
    Integer b("98765432109876543210");

    std::cout << "a = " << a << std::endl;
    std::cout << "b = " << b << std::endl;
    std::cout << "a + b = " << (a + b) << std::endl;
    std::cout << "a * b = " << (a * b) << std::endl;
    std::cout << "b / a = " << (b / a) << std::endl;
    std::cout << "b % a = " << (b % a) << std::endl;

    return 0;
}
```

### Example 2: RSA Key Components

```cpp
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Generate two 512-bit primes
    Integer p = MaurerProvablePrime(rng, 512);
    Integer q = MaurerProvablePrime(rng, 512);

    // RSA modulus
    Integer n = p * q;

    // Euler's totient
    Integer phi = (p - 1) * (q - 1);

    // Public exponent
    Integer e(65537);

    // Private exponent
    Integer d = e.InverseMod(phi);

    std::cout << "p bits: " << p.BitCount() << std::endl;
    std::cout << "q bits: " << q.BitCount() << std::endl;
    std::cout << "n bits: " << n.BitCount() << std::endl;
    std::cout << "e = " << e << std::endl;

    // Verify: e * d ≡ 1 (mod phi)
    Integer check = (e * d) % phi;
    std::cout << "e * d mod phi = " << check << std::endl;

    return 0;
}
```

### Example 3: Modular Exponentiation

```cpp
#include <cryptopp/integer.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Compute 2^1000 mod 1000000007
    Integer base(2);
    Integer exp(1000);
    Integer mod(1000000007);

    Integer result = a_exp_b_mod_c(base, exp, mod);

    std::cout << "2^1000 mod 1000000007 = " << result << std::endl;

    // Alternative using method
    result = base.ModularExponentiation(exp, mod);
    std::cout << "Same result: " << result << std::endl;

    return 0;
}
```

### Example 4: GCD and Extended Euclidean

```cpp
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    Integer a(48);
    Integer b(18);

    // GCD
    Integer gcd = GCD(a, b);
    std::cout << "GCD(" << a << ", " << b << ") = " << gcd << std::endl;

    // Extended Euclidean: find x, y such that ax + by = gcd(a,b)
    Integer x, y;
    Integer g = EuclideanMultiplicativeInverse(a, b);
    std::cout << "Inverse of " << a << " mod " << b << " = " << g << std::endl;

    // LCM
    Integer lcm = LCM(a, b);
    std::cout << "LCM(" << a << ", " << b << ") = " << lcm << std::endl;

    return 0;
}
```

### Example 5: Prime Testing

```cpp
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/osrng.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Test if a number is prime
    Integer candidate("104729");  // This is prime
    bool isPrime = IsPrime(candidate);
    std::cout << candidate << " is prime: " << (isPrime ? "yes" : "no") << std::endl;

    // Miller-Rabin test with custom rounds
    Integer large("170141183460469231731687303715884105727");  // Mersenne prime M_127
    bool isProbablyPrime = IsStrongProbablePrime(large, 2);  // Base 2
    std::cout << "M_127 is probably prime: " << (isProbablyPrime ? "yes" : "no") << std::endl;

    // Generate random prime
    Integer prime = MaurerProvablePrime(rng, 256);
    std::cout << "Random 256-bit prime: " << std::hex << prime << std::endl;

    return 0;
}
```

### Example 6: Byte Array Conversion

```cpp
#include <cryptopp/integer.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    // Create integer from hex string
    Integer num("0xDEADBEEFCAFEBABE");

    // Get byte count
    size_t byteCount = num.ByteCount();
    std::cout << "Byte count: " << byteCount << std::endl;

    // Encode to bytes (big-endian)
    std::vector<byte> buffer(byteCount);
    num.Encode(buffer.data(), byteCount);

    // Print as hex
    std::string hex;
    StringSource(buffer.data(), buffer.size(), true,
        new HexEncoder(new StringSink(hex))
    );
    std::cout << "Hex: " << hex << std::endl;

    // Decode back
    Integer decoded;
    decoded.Decode(buffer.data(), buffer.size());
    std::cout << "Decoded: 0x" << std::hex << decoded << std::endl;

    return 0;
}
```

### Example 7: Diffie-Hellman Parameters

```cpp
#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/nbtheory.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Standard DH parameters (2048-bit MODP group)
    // In practice, use predefined groups like RFC 3526

    // Generate safe prime p = 2q + 1
    Integer q = MaurerProvablePrime(rng, 256);  // Small for demo
    Integer p = 2 * q + 1;

    // Check if p is prime
    while (!IsPrime(p)) {
        q = MaurerProvablePrime(rng, 256);
        p = 2 * q + 1;
    }

    // Generator g = 2 (for safe primes)
    Integer g(2);

    std::cout << "Safe prime p bits: " << p.BitCount() << std::endl;

    // Alice's private key
    Integer a(rng, 2, p - 2);
    // Alice's public key
    Integer A = a_exp_b_mod_c(g, a, p);

    // Bob's private key
    Integer b(rng, 2, p - 2);
    // Bob's public key
    Integer B = a_exp_b_mod_c(g, b, p);

    // Shared secret
    Integer secretA = a_exp_b_mod_c(B, a, p);
    Integer secretB = a_exp_b_mod_c(A, b, p);

    std::cout << "Secrets match: " << (secretA == secretB ? "yes" : "no") << std::endl;

    return 0;
}
```

### Example 8: Jacobi Symbol

```cpp
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <iostream>

int main() {
    using namespace CryptoPP;

    Integer a(1001);
    Integer n(9907);  // Prime

    int jacobi = Jacobi(a, n);
    std::cout << "Jacobi(" << a << "/" << n << ") = " << jacobi << std::endl;

    // For prime n, Jacobi = Legendre symbol
    // 1 means a is quadratic residue mod n
    // -1 means a is not a quadratic residue
    // 0 means a ≡ 0 (mod n)

    return 0;
}
```

## Number Theory Functions

From `<cryptopp/nbtheory.h>`:

```cpp
// GCD and LCM
Integer GCD(const Integer& a, const Integer& b);
Integer LCM(const Integer& a, const Integer& b);

// Primality testing
bool IsPrime(const Integer& p);
bool IsStrongProbablePrime(const Integer& n, const Integer& b);
bool RabinMillerTest(RandomNumberGenerator& rng, const Integer& n, unsigned int rounds);

// Prime generation
Integer MaurerProvablePrime(RandomNumberGenerator& rng, unsigned int bits);

// Modular arithmetic
Integer EuclideanMultiplicativeInverse(const Integer& a, const Integer& n);
Integer ModularSquareRoot(const Integer& a, const Integer& p);

// Jacobi/Legendre symbol
int Jacobi(const Integer& a, const Integer& n);
```

## Performance Considerations

```cpp
// Prefer in-place operations
Integer a(100);
a += 50;           // Faster than a = a + 50

// Use Montgomery multiplication for repeated mod operations
// (Crypto++ does this internally for modular exponentiation)

// Pre-compute for multiple exponentiations with same base
// Use ModularArithmetic class for repeated operations mod same modulus
```

## Memory Considerations

```cpp
// Integer automatically manages memory
// For sensitive values, consider:

#include <cryptopp/secblock.h>

// After using sensitive integers
Integer privateKey = ...;
// ... use it ...

// Explicitly clear (though destructor also clears)
privateKey = Integer::Zero();
```

## Thread Safety

- Read operations are thread-safe
- Modification operations are not thread-safe
- Use separate Integer objects per thread for writes

```cpp
// WRONG - concurrent modification
Integer shared;
// Thread 1: shared += 1;
// Thread 2: shared += 2;

// CORRECT - per-thread or synchronized
void computeInThread() {
    Integer local(100);
    local += 50;  // Safe
}
```

## Error Handling

```cpp
#include <cryptopp/integer.h>
#include <iostream>

void safeOperation() {
    using namespace CryptoPP;

    try {
        Integer a(10);
        Integer b(0);

        // Division by zero throws
        Integer result = a / b;

    } catch (const Integer::DivideByZero& e) {
        std::cerr << "Division by zero!" << std::endl;

    } catch (const Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}
```

## See Also

- [RSA](/docs/api/pubkey/rsa/) - RSA encryption using Integer
- [AutoSeededRandomPool](/docs/api/utilities/autoseededrandompool/) - Random number generation
- [SecByteBlock](/docs/api/utilities/secbyteblock/) - Secure memory
- [X25519](/docs/api/pubkey/x25519/) - Modern key exchange (alternative to DH)
