
#include "Common.h"
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>
#include <secp256k1_sha256.h>
#include "../App/Enclave_u.h"
#include "sgx_urts.h"


using namespace std;
using namespace dev;
using namespace dev::crypto;
extern sgx_enclave_id_t eid;
namespace {
    secp256k1_context const *getCtx() {
        static std::unique_ptr<secp256k1_context, decltype(&secp256k1_context_destroy)> s_ctx{
                secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY),
                &secp256k1_context_destroy
        };
        return s_ctx.get();
    }
    template <std::size_t KeySize>

    bool toPublicKey(Secret const& _secret, unsigned _flags, array<byte, KeySize>& o_serializedPubkey)
    {
        auto* ctx = getCtx();
        secp256k1_pubkey rawPubkey;
        // Creation will fail if the secret key is invalid.
        if (!secp256k1_ec_pubkey_create(ctx, &rawPubkey, _secret.data()))
            return false;
        size_t serializedPubkeySize = o_serializedPubkey.size();
        secp256k1_ec_pubkey_serialize(
                ctx, o_serializedPubkey.data(), &serializedPubkeySize, &rawPubkey, _flags);
        assert(serializedPubkeySize == o_serializedPubkey.size());
        return true;
    }
}
static const u256 c_secp256k1n("115792089237316195423570985008687907852837564279074904382605163141518161494337");

Signature dev::enclave_sign(h256 const& _hash){
    SignatureStruct ss;
    byte *vv = &(ss.v);
    int ret = ecdsa_sign_m(eid, &ret, _hash.data(), 32, ss.r.ref().data(), ss.s.ref().data(),vv);
   if(ret != 0) {
////        error
        printf("sign error\n");
        return ss;
    }
    ss.v -= 27;
//    cout << "rsv:\nr: "<< ss.r << "\ns: " << ss.s << "\nv: " << (int)ss.v << "\n";
//    cout << "what ()" <<  c_secp256k1n / 2 << endl;
    return ss;
}
Signature dev::sign(Secret const &_k, h256 const &_hash) {
    auto *ctx = getCtx();
    secp256k1_ecdsa_recoverable_signature rawSig;
    // _hash.data() byte const * (uint8_t *)
    // _k.data()  byte const *
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &rawSig, _hash.data(), _k.data(), nullptr, nullptr)){
        cout << "secp256k1_ecdsa_sign_recoverable\n";
        return {};
    }

    Signature s;
    int v = 0;
    // s.data() byte const * (uint8_t *)
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, s.data(), &v, &rawSig);

    SignatureStruct &ss = *reinterpret_cast<SignatureStruct *>(&s);
    ss.v = static_cast<byte>(v);
    if (ss.s > c_secp256k1n / 2) {
        ss.v = static_cast<byte>(ss.v ^ 1);
        ss.s = h256(c_secp256k1n - u256(ss.s));
    }
    assert(ss.s <= c_secp256k1n / 2);
    cout << "rsv:\nr: "<< ss.r << "\ns: " << ss.s << "\nv: " << (int)ss.v << "\n\n";
    return s;
}

Public dev::recover(Signature const& _sig, h256 const& _message)
{
    int v = _sig[64];
    if (v > 3)
        return {};

    auto* ctx = getCtx();
    secp256k1_ecdsa_recoverable_signature rawSig;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rawSig, _sig.data(), v))
        return {};

    secp256k1_pubkey rawPubkey;
    if (!secp256k1_ecdsa_recover(ctx, &rawPubkey, &rawSig, _message.data()))
        return {};

    std::array<byte, 65> serializedPubkey;
    size_t serializedPubkeySize = serializedPubkey.size();
    secp256k1_ec_pubkey_serialize(
            ctx, serializedPubkey.data(), &serializedPubkeySize,
            &rawPubkey, SECP256K1_EC_UNCOMPRESSED
    );
    assert(serializedPubkeySize == serializedPubkey.size());
    // Expect single byte header of value 0x04 -- uncompressed public key.
    assert(serializedPubkey[0] == 0x04);
    // Create the Public skipping the header.
    return Public{&serializedPubkey[1], Public::ConstructFromPointer};
}

bool dev::SignatureStruct::isValid() const noexcept
{
    static const h256 s_max{"0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"};
    static const h256 s_zero;

    return (v <= 1 && r > s_zero && s > s_zero && r < s_max && s < s_max);
}



//h256 crypto::kdf(Secret const &_priv, h256 const &_hash) {
//    // H(H(r||k)^h)
//    h256 s;
//    sha3mac(Secret::random().ref(), _priv.ref(), s.ref());
//    s ^= _hash;
//    sha3(s.ref(), s.ref());
//
//    if (!s || !_hash || !_priv)
//        BOOST_THROW_EXCEPTION(InvalidState());
//    return s;
//}

KeyPair KeyPair::create()
{
    while (true)
    {
        KeyPair keyPair(Secret::random());
        if (keyPair.address())
            return keyPair;
    }
}

KeyPair::KeyPair(Secret const& _sec):
        m_secret(_sec),
        m_public(toPublic(_sec))
{
    // Assign address only if the secret key is valid.
    if (m_public)
        m_address = toAddress(m_public);
}

Address dev::toAddress(Public const& _public)
{
    return right160(sha3(_public.ref()));
}

Public dev::toPublic(Secret const& _secret)
{
    std::array<byte, 65> serializedPubkey;
    if (!toPublicKey(_secret, SECP256K1_EC_UNCOMPRESSED, serializedPubkey))
        return {};

    // Expect single byte header of value 0x04 -- uncompressed public key.
    assert(serializedPubkey[0] == 0x04);

    // Create the Public skipping the header.
    return Public{&serializedPubkey[1], Public::ConstructFromPointer};
}