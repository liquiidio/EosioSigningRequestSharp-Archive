
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EosioSigningRequest;
using EosSharp.Core.Api.v1;

namespace EosioSigningRequest
{
    using IdentityProofType = System.Object;
    using PublicKey = String;
/*    | IdentityProof
    | string
    | {
          chainId: ChainIdType
          scope: NameType
          expiration: TimePointType
          signer: PermissionLevelType
          signature: SignatureType*/

    public class IdentityProof
    {
        public string chainId;
        public string scope;
        public DateTime expiration;
        public PermissionLevel signer;
        public string signature;


        static IdentityProof from(IdentityProofType value)
        {
            if (value is IdentityProof)
            {
                return value as IdentityProof;
            }
            else if (value is string s)
            {
                return IdentityProof.fromString(s);
            }
            else
            {
                return null;
            }
        }

        /**
         * Create a new instance from an EOSIO authorization header string.
         * "EOSIO <base64payload>"
         */
        static IdentityProof fromString(string str)
        {
            string[] parts = str.Split(' '); 
            
            if (parts.Length != 2 || parts[0] != "EOSIO")
            {
                throw new Exception("Invalid IdentityProof string");
            }

            return new IdentityProof(); // TODO deserialize via AbiDecoder
    //        const data = Base64u.decode(parts[1])
    //            return Serializer.decode({ data, type: IdentityProof})
        }

        /** Create a new instance from a callback payload. */
        static IdentityProof fromPayload(CallbackPayload payload, SigningRequestEncodingOptions options = null)
        {
            var request = SigningRequest.from(payload.req, options);
                if (!(request.version >= 3 && request.isIdentity()))
                {
                    throw new Exception("Not an identity request");
                }

                return new IdentityProof()
                {
                    chainId = payload.cid ?? request.getChainId(),
                    scope = request.getIdentityScope()!,
                    expiration = payload.ex,
                    signer =  new PermissionLevel(){actor = payload.sa, permission = payload.sp},
                    signature = payload.sig,
                };
        }

        /**
         * Transaction this proof resolves to.
         * @internal
         */
        Transaction transaction()
        {
            var action = new EosSharp.Core.Api.v1.Action(){
                    account = "",
                    name = "identity",
                    authorization = new List<PermissionLevel> {this.signer},
                    data = null //IdentityV3.from({ scope: this.scope, permission: this.signer}), TODO
                };

            return new Transaction()
            {
                ref_block_num = 0,
                ref_block_prefix = 0,
                expiration = this.expiration,
                actions = new List<EosSharp.Core.Api.v1.Action> {action},
            };
        }

        /**
         * Recover the public key that signed this proof.
         */
        PublicKey recover()
        {
            return signature;
// TODO            return this.signature.recoverDigest(this.transaction.signingDigest(this.chainId));
        }

    /**
     * Verify that given authority signed this proof.
     * @param auth The accounts signing authority.
     * @param currentTime Time to verify expiry against, if unset will use system time.
     */
    bool verify(Authority auth, DateTime? currentTime)
    {
        var now = ((DateTimeOffset) (currentTime ?? new DateTime())).ToUnixTimeMilliseconds();
        return (
            now < ((DateTimeOffset) this.expiration).ToUnixTimeMilliseconds() &&
            auth.hasPermission(this.recover())
        );
    }

    /**
     * Encode the proof to an `EOSIO` auth header string.
     */
//    string toString() {
//        const data = Serializer.encode({ object: this})
//            return $"EOSIO { Base64u.encode(data.array, false)}"
//        }
    }
}
