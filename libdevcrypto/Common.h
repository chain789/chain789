#pragma once

#include <libdevcore/Address.h>
#include <libdevcore/Common.h>
#include <libdevcore/Exceptions.h>
#include <libdevcore/FixedHash.h>
#include <libdevcore/SHA3.h>

namespace dev
{
    using Secret = SecureFixedHash<32>;

    /// A public key: 64 bytes.
    /// @NOTE This is not endian-specific; it's just a bunch of bytes.
    using Public = h512;

    /// A public key in compressed format: 33 bytes.
    /// @NOTE This is not endian-specific; it's just a bunch of bytes.
    using PublicCompressed = FixedHash<33>;

    /// A signature: 65 bytes: r: [0, 32), s: [32, 64), v: 64.
    /// @NOTE This is not endian-specific; it's just a bunch of bytes.
    using Signature = h520;

    /// Convert a public key to address.
    Address toAddress(Public const& _public);
    /// Convert a secret key into the public key equivalent.
    Public toPublic(Secret const& _secret);

    struct SignatureStruct
    {
        SignatureStruct() = default;
        SignatureStruct(Signature const& _s) { *(h520*)this = _s; }
        SignatureStruct(h256 const& _r, h256 const& _s, byte _v): r(_r), s(_s), v(_v) {}
        operator Signature() const { return *(h520 const*)this; }

        /// @returns true if r,s,v values are valid, otherwise false
        bool isValid() const noexcept;

        h256 r;
        h256 s;
        byte v = 0;
    };

    /// Returns siganture of message hash.
    Signature sign(Secret const& _k, h256 const& _hash);
    Signature enclave_sign(h256 const& _hash);

    /// Verify signature.
    bool verify(Public const& _k, Signature const& _s, h256 const& _hash);

    // Verify signature with compressed public key
    bool verify(PublicCompressed const& _key, h512 const& _signature, h256 const& _hash);

    /// Recovers Public key from signed message hash.
    Public recover(Signature const& _sig, h256 const& _hash);

    /// Simple class that represents a "key pair".
    /// All of the data of the class can be regenerated from the secret key (m_secret) alone.
    /// Actually stores a tuplet of secret, public and address (the right 160-bits of the public).
    class KeyPair
    {
    public:
        /// Normal constructor - populates object from the given secret key.
        /// If the secret key is invalid the constructor succeeds, but public key
        /// and address stay "null".
        KeyPair(Secret const& _sec);

        /// Create a new, randomly generated object.
        static KeyPair create();

        /// Create from an encrypted seed.
//        static KeyPair fromEncryptedSeed(bytesConstRef _seed, std::string const& _password);

        Secret const& secret() const { return m_secret; }

        /// Retrieve the public key.
        Public const& pub() const { return m_public; }

        /// Retrieve the associated address of the public key.
        Address const& address() const { return m_address; }

        bool operator==(KeyPair const& _c) const { return m_public == _c.m_public; }
        bool operator!=(KeyPair const& _c) const { return m_public != _c.m_public; }

    private:
        Secret m_secret;
        Public m_public;
        Address m_address;
    };
    namespace crypto{

    }
}