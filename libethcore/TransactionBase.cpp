#include "TransactionBase.h"

using namespace std;
using namespace dev;
using namespace dev::eth;


Address const& TransactionBase::safeSender() const noexcept
{
	try
	{
		return sender();
	}
	catch (...)
	{
		return ZeroAddress;
	}
}

Address const& TransactionBase::sender() const
{
    if (!m_sender.is_initialized())
	{
		if (hasZeroSignature())
			m_sender = MaxAddress;
		else
		{
			if (!m_vrs)
				BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

			auto p = recover(*m_vrs, sha3(WithoutSignature));
			if (!p)
				BOOST_THROW_EXCEPTION(InvalidSignature());
			m_sender = right160(dev::sha3(bytesConstRef(p.data(), sizeof(p))));
		}
	}
    return *m_sender;
}

SignatureStruct const& TransactionBase::signature() const
{ 
	if (!m_vrs)
		BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

	return *m_vrs;
}

void TransactionBase::sign(Secret const& _priv)
{
	auto sig = dev::sign(_priv, sha3(WithoutSignature));
	SignatureStruct sigStruct = *(SignatureStruct const*)&sig;
	if (sigStruct.isValid())
		m_vrs = sigStruct;
}

void TransactionBase::enclave_sign(){
    auto sig = dev::enclave_sign(sha3(WithoutSignature));
    SignatureStruct sigStruct = *(SignatureStruct const*)&sig;
    m_vrs = sigStruct;
//    if (sigStruct.isValid()){
//        cout << "TransactionBase::enclave_sign return SUCCESS\n";
//
//    } else {
//        cout << "TransactionBase::enclave_sign error\n";
//        exit(-1);
//    }
}


static const u256 c_secp256k1n("115792089237316195423570985008687907852837564279074904382605163141518161494337");

void TransactionBase::streamRLP(RLPStream& _s, IncludeSignature _sig, bool _forEip155hash) const
{
    if (m_type == NullTransaction)
        return;

    _s.appendList((_sig || _forEip155hash ? 3 : 0) + 6);
    _s << m_nonce << m_gasPrice << m_gas;
    if (m_type == MessageCall)
        _s << m_receiveAddress;
    else
        _s << "";
    _s << m_value << m_data;

    if (_sig)
    {
        if (!m_vrs)
            BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

        if (hasZeroSignature())
            _s << m_chainId;
        else
        {
            int const vOffset = m_chainId * 2 + 35;
            _s << (m_vrs->v + vOffset);
        }
        _s << (u256)m_vrs->r << (u256)m_vrs->s;
    }
    else if (_forEip155hash)
        _s << m_chainId << 0 << 0;
}

h256 TransactionBase::sha3(IncludeSignature _sig) const
{
	if (_sig == WithSignature && m_hashWith)
		return m_hashWith;

	RLPStream s;
	streamRLP(s, _sig, m_chainId > 0 && _sig == WithoutSignature);

	auto ret = dev::sha3(s.out());
	if (_sig == WithSignature)
		m_hashWith = ret;
	return ret;
}
