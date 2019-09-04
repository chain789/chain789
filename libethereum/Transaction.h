#include <libethcore/TransactionBase.h>
#include <libdevcore/RLP.h>
#include <libdevcore/SHA3.h>

namespace dev {
    namespace eth {

        /// Description of the result of executing a transaction.
//        struct ExecutionResult {
//            u256 gasUsed = 0;
//            TransactionException excepted = TransactionException::Unknown;
//            Address newAddress;
//            bytes output;
//            CodeDeposit codeDeposit = CodeDeposit::None;                    ///< Failed if an attempted deposit failed due to lack of gas.
//            u256 gasRefunded = 0;
//            unsigned depositSize = 0;                                        ///< Amount of code of the creation's attempted deposit.
//            u256 gasForDeposit;                                            ///< Amount of gas remaining for the code deposit phase.
//        };

//        std::ostream &operator<<(std::ostream &_out, ExecutionResult const &_er);

/// Encodes a transaction, ready to be exported to or freshly imported from RLP.
        class Transaction : public TransactionBase {
        public:
            /// Constructs a null transaction.
            Transaction() {}

            /// Constructs from a transaction skeleton & optional secret.
//	Transaction(TransactionSkeleton const& _ts, Secret const& _s = Secret()): TransactionBase(_ts, _s) {}

            /// Constructs a signed message-call transaction.
            Transaction(u256 const &_value, u256 const &_gasPrice, u256 const &_gas, Address const &_dest,
                        bytes const &_data, u256 const &_nonce, Secret const &_secret) :
                    TransactionBase(_value, _gasPrice, _gas, _dest, _data, _nonce, _secret) {}

            /// Constructs a signed contract-creation transaction.
            Transaction(u256 const &_value, u256 const &_gasPrice, u256 const &_gas, bytes const &_data,
                        u256 const &_nonce, Secret const &_secret) :
                    TransactionBase(_value, _gasPrice, _gas, _data, _nonce, _secret) {}

            /// Constructs an unsigned message-call transaction.
            Transaction(u256 const &_value, u256 const &_gasPrice, u256 const &_gas, Address const &_dest,
                        bytes const &_data, u256 const &_nonce = Invalid256) :
                    TransactionBase(_value, _gasPrice, _gas, _dest, _data, _nonce) {}

            /// Constructs an unsigned contract-creation transaction.
            Transaction(u256 const &_value, u256 const &_gasPrice, u256 const &_gas, bytes const &_data,
                        u256 const &_nonce = Invalid256) :
                    TransactionBase(_value, _gasPrice, _gas, _data, _nonce) {}

            /// Constructs a transaction from the given RLP.
//	explicit Transaction(bytesConstRef _rlp, CheckTransaction _checkSig);

            /// Constructs a transaction from the given RLP.
//	explicit Transaction(bytes const& _rlp, CheckTransaction _checkSig): Transaction(&_rlp, _checkSig) {}
        };
    }
}