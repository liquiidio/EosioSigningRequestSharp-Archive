/**
 * EOSIO Signing Request (ESR).
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Cryptography.ECDSA;
using EosSharp;
using EosSharp.Core;
using EosSharp.Core.Api.v1;
using EosSharp.Core.Helpers;
using EosSharp.Core.Providers;
using Newtonsoft.Json;

using CallbackType = System.Object; // TODO export type CallbackType = string | {url: string; backgroundBit: boolean}*/
using AbiMap = System.Collections.Generic.Dictionary<string, EosSharp.Core.Api.v1.Abi>; //     export type AbiMap = Map<string, any>
using Action = EosSharp.Core.Api.v1.Action;
using ChainId = System.String; /*checksum256*/
using VariantId = System.Tuple<string, object>;
using SignatureType = System.Object;

namespace EosioSigningRequest
{
    public class CallbackObj
    {
        public string url;
        public bool background;
    }

    public static class Constants
    {
        public static Dictionary<ChainName, string> ChainIdLookup = new Dictionary<ChainName, string>() {
            {ChainName.EOS, "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906"},
            {ChainName.TELOS, "4667b205c6838ef70ff7988f6e8257e8be0e1284a2f59699054a018f743b1d11"},
            {ChainName.JUNGLE, "e70aaab8997e1dfce58fbfac80cbbb8fecec7b99cf982a9444273cbc64c41473"},
            {ChainName.KYLIN, "5fff1dae8dc8e2fc4d5b23b2c7665c97f9e9d8edf2b6485a86ba311c25639191"},
            {ChainName.WORBLI, "73647cde120091e0a4b85bced2f3cfdb3041e266cbbe95cee59b73235a1b3b6f"},
            {ChainName.BOS, "d5a3d18fbb3c084e3b1f3fa98c21014b5f3db536cc15d08f9f6479517c6a3d86"},
            {ChainName.MEETONE, "cfe6486a83bad4962f232d48003b1824ab5665c36778141034d75e57b956e422"},
            {ChainName.INSIGHTS, "b042025541e25a472bffde2d62edd457b7e70cee943412b1ea0f044f88591664"},
            {ChainName.BEOS, "b912d19a6abd2b1b05611ae5be473355d64d95aeff0c09bedc8c166cd6468fe4"},
            {ChainName.WAX, "1064487b3cd1a897ce03ae5b6a865651747e2e152090f99c1d19d44e01aea5a4"},
            {ChainName.PROTON, "384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0"},
            {ChainName.FIO, "21dcae42c0182200e93f954a074011f9048a7624c6fe81d3c9541a614a88bd1c"} 
        };

        public static string PlaceholderName = "............1";

        public static string PlaceholderPermission = "............2";

        public static byte ProtocolVersion = 2;

        public static EosSharp.Core.Api.v1.PermissionLevel PlaceholderAuth = new EosSharp.Core.Api.v1.PermissionLevel()
        {
            actor = PlaceholderName,
            permission = PlaceholderPermission
        };

        public static bool isIdentity(EosSharp.Core.Api.v1.Action action)
        {
            return action.account == "" && action.name == "identity";
        }

        public static bool hasTapos(EosSharp.Core.Api.v1.Transaction tx)
        {
            return !(tx.expiration == new DateTime(1970, 1, 1) && tx.ref_block_num == 0 && tx.ref_block_prefix == 0);
        }

        public static VariantId variantId(object chainId /*abi.ChainId | abi.ChainAlias*/){
            if (chainId == null)
            {
                chainId = ChainName.EOS;
            }
            if (chainId is int)
            {
                return new VariantId("chain_alias", chainId);
            } 
            else
            {
                Console.WriteLine(chainId.GetType().ToString());
                var t = chainId.GetType();
                // resolve known chain id's to their aliases
                var _name = ChainIdLookup.SingleOrDefault(v => v.Value == chainId.ToString()).Key;
                string name = _name.ToString();
                if (string.IsNullOrEmpty(name))// ChainName.UNKNOWN ?
                {
                    return new VariantId("chain_id", name);
                }

                return new VariantId("chain_id", chainId);
            }
        }

        public static string nameToId(long id)
        {
            // TODO
            return "";
        }
    }

    /*import {Serialize} from 'eosjs'
    import sha256 from 'fast-sha256'*/

    /*import * as abi from './abi'
    import * as base64u from './base64u'

    const ProtocolVersion = 2

    const AbiTypes = Serialize.getTypesFromAbi(Serialize.createInitialTypes(), abi.data as any)*/

    /** Interface that should be implemented by abi providers. */
/*    public interface IAbiProvider
    {
        /**
     * Return a promise that resolves to an abi object for the given account name,
     * e.g. the result of a rpc call to chain/get_abi.
     */
        //Task<object> getAbi(string account);//: (account: string) => Promise<any>
    //}

    /** Interface that should be implemented by zlib implementations. */
    public interface IZlibProvider
    {
        /** Deflate data w/o adding zlib header. */
        byte[] deflateRaw(byte[] data);

        /** Inflate data w/o requiring zlib header. */
        byte[] inflateRaw(byte[] data);
    }

    /** Interface that should be implemented by signature providers. */
    public interface ISignatureProvider
    {
        /** Sign 32-byte hex-encoded message and return signer name and signature string. */
        RequestSignature sign(string message);// => {signer: string; signature: string}  // TODO
    }

    /**
     * The callback payload sent to backgroundBit callbacks.
     */
    public class CallbackPayload
    {
        /** The first signature. */
        public string sig;

        /** Transaction ID as HEX-encoded string. */
        public string tx;

        /** Block number hint (only present if transaction was broadcastBit). */
        public string bn;

        /** Signer authority, aka account name. */
        public string sa;

        /** Signer permission, e.g. "active". */
        public string sp;

        /** Reference block num used when resolving request. */
        public string rbn;

        /** Reference block id used when resolving request. */
        public string rid;

        /** The originating signing request packed as a uri string. */
        public string req;

        /** Expiration time used when resolving request. */
        public DateTime ex;

        /** All signatures 0-indexed as `sig0`, `sig1`, etc. */
        public Dictionary<string, string> sigs;
        //    [sig0: string]: string | undefined    // TODO
        public Dictionary<string, string> data;

        public string cid;
    }

    /**
     * Context used to resolve a callback.
     * Compatible with the JSON response from a `push_transaction` call.
     */
    public class ResolvedCallback
    {
        /** The URL to hit. */
        public string url;

        /**
         * Whether to run the request in the backgroundBit. For a https url this
         * means POST in the backgroundBit instead of a GET redirect.
         */
        public bool background;

        /**
         * The callback payload as a object that should be encoded to JSON
         * and POSTed to backgroundBit callbacks.
         */
        public CallbackPayload payload;
    }

    /**
     * Context used to resolve a transaction.
     * Compatible with the JSON response from a `get_block` call.
     */
    public class TransactionContext
    {
        /** Timestamp expiration will be derived from. */
        public DateTime? timestamp;

        /**
         * How many seconds in the future to set expiration when deriving from timestamp.
         * Defaults to 60 seconds if unset.
         */
        public uint? expire_seconds;

        /** Block number ref_block_num will be derived from. */
        public uint? block_num;

        /** Reference block number, takes precedence over block_num if both is set. */
        public uint? ref_block_num;

        /** Reference block prefix. */
        public uint? ref_block_prefix;

        /** Expiration timestamp, takes precedence over timestamp and expire_seconds if set. */
        public DateTime? expiration;
    }

    /** Chain ID aliases. */
    public enum ChainName
    {
        UNKNOWN = 0, // reserved
        EOS = 1,
        TELOS = 2,
        JUNGLE = 3,
        KYLIN = 4,
        WORBLI = 5,
        BOS = 6,
        MEETONE = 7,
        INSIGHTS = 8,
        BEOS = 9,
        WAX = 10,
        PROTON = 11,
        FIO = 12,
    }

    public class SigningRequestCreateArguments
    {

        /** Single action to create request with. */
        public EosSharp.Core.Api.v1.Action action;
        //public Action action;

        /** Multiple actions to create request with. */
        public EosSharp.Core.Api.v1.Action[] actions;

        /**
         * Full or partial transaction to create request with.
         * If TAPoS info is omitted it will be filled in when resolving the request.
         */
        public EosSharp.Core.Api.v1.Transaction transaction;

        /** Create an identity request. */
        public Identity identity;

        /** Chain to use, defaults to EOS main-net if omitted. */
        public string chainId;

        /** Whether wallet should broadcastBit tx, defaults to true. */
        public bool? broadcast;

        /**
        * Optional callback URL the signer should hit after
        * broadcasting or signing. Passing a string means backgroundBit = false.
        */
        public CallbackType callback;

        public string[] chainIds;

        /** Optional metadata to pass along with the request. */
        public object info; // {[key: string]: string | Uint8Array}   // TODO
        // Dictionary or string ?
    }

    public class SigningRequestCreateIdentityArguments
    {
        /**
     * Callback where the identity should be delivered.
     */
        public CallbackType callback;

        /** Chain to use, defaults to EOS if omitted. */
        public string chainId;

        /**
         * Requested account name of identity.
         * Defaults to placeholder (any identity) if omitted.
         */
        public string account;

        /**
         * Requested account permission.
         * Defaults to placeholder (any permission) if omitted.
         */
        public string permission;

        /** Optional metadata to pass along with the request. */
        public object info; // {[key: string]: string | Uint8Array}
    }

    public class SigningRequestEncodingOptions
    {
        public IZlibProvider zlib;

        /** Abi provider, required if the arguments contain un-encoded actions. */
        public IAbiProvider abiProvider;
        
        /** Optional signature provider, will be used to create a request signature if provided. */
        public ISignatureProvider signatureProvider;
    }

    public class SigningRequest
    {
        public static AbiStruct type = EosioSigningRequestAbiData.Data.structs.SingleOrDefault(s => s.name == "signing_request");
        public static AbiStruct idType = EosioSigningRequestAbiData.Data.structs.SingleOrDefault(s => s.name == "identity");
        public static AbiStruct transactionType = EosioSigningRequestAbiData.Data.structs.SingleOrDefault(s => s.name == "transaction");

        /** Create a new signing request. */
        public static async Task<SigningRequest> create(SigningRequestCreateArguments args, SigningRequestEncodingOptions options = null) {

            object[] actions;
            if (args.action != null)
            {
                actions = new[] {args.action};
            }
            else if (args.actions != null)
            {
                actions = args.actions;
            }
            else if (args.transaction != null)
            {
                actions = args.transaction.actions?.ToArray() ?? new object[] { };
            }
            else
            {
                actions = new object[0];
            }

            var requiredAbis = actions.Where(a => a is Action action && action.data is byte[]).Select(action => (action as Action)?.account).ToList();

            Dictionary<string, Abi> abis = new AbiMap();
            if (requiredAbis.Count > 0)
            {
                var provider = options?.abiProvider;
                if (provider == null)
                {
                    throw new Exception("Missing abi provider");
                }

                abis = (await Task.WhenAll(requiredAbis.Select(async a =>
                        new KeyValuePair<string, Abi>(a, await provider.GetAbi(a)))))
                    .ToDictionary(a => a.Key, a => a.Value);
            }

            return await createSync(args, options, abis);


/*          async Task<EosSharp.Core.Api.v1.Action> serialize(EosSharp.Core.Api.v1.Action action)
            {
                EosApi eosApi = new EosApi(new EosConfigurator(), new HttpHandler());    // TODO Unity-Specific HttpHandler

                var abi = (await eosApi.GetAbi(new GetAbiRequest() { account_name = action.account }, true)).abi;
                AbiSerializationProvider abiSerializationProvider = new AbiSerializationProvider(eosApi);
                action.data = abiSerializationProvider.SerializeActionData(action, abi);    // TODO hm. weird way ... 
                return action;
            }

            SigningRequestData data = null;

            // set the request data
            if (args.identity != null)
            {
                data.req = new Tuple<string, object>("identity",args.identity);
            }
            else if (args.action != null && args.actions == null && args.transaction == null)
            {
                data.req = new Tuple<string, object>("action", await serialize(args.action));
            }
            else if (args.actions != null && args.action == null && args.transaction == null)
            {
                if (args.actions.Length == 1)
                {
                    data.req = new Tuple<string, object>("action", await serialize(args.actions[0]));
                }
                else
                {
                    data.req = new Tuple<string, object>("actions", args.actions.Select(async action => await serialize(action)).Select(t => t.Result).ToArray());
                }
            }
            else if (args.transaction != null && args.action == null && args.actions == null)
            {
                var tx = args.transaction;
                // set default values if missing
                if (tx.expiration == null)
                {
                    tx.expiration = new DateTime(1970, 1, 1);
                }

                if (tx.ref_block_num == null)
                {
                    tx.ref_block_num = 0;
                }

                if (tx.ref_block_prefix == null)
                {
                    tx.ref_block_prefix = 0;
                }

                if (tx.context_free_actions == null)
                {
                    tx.context_free_actions = new List<EosSharp.Core.Api.v1.Action>();
                }

                if (tx.transaction_extensions == null)
                {
                    tx.transaction_extensions = new List<EosSharp.Core.Api.v1.Extension>();
                }

                if (tx.delay_sec == null)
                {
                    tx.delay_sec = 0;
                }

                if (tx.max_cpu_usage_ms == null)
                {
                    tx.max_cpu_usage_ms = 0;
                }

                if (tx.max_net_usage_words == null)
                {
                    tx.max_net_usage_words = 0;
                }

                // encode actions if needed
                tx.actions = tx.actions.Select(async action => await serialize(action)).Select(t => t.Result).ToList();
                data.req = new Tuple<string, object>("transaction", tx);
            }
            else
            {
                throw new Exception("Invalid arguments: Must have exactly one of action, actions or transaction");
            }

            // set the chain id
            data.chain_id = Constants.variantId(args.chainId);
            data.flags = AbiConstants.RequestFlagsNone;

            bool broadcastBit = args.broadcastBit ?? true;
            if (broadcastBit)
            {
                data.flags |= AbiConstants.RequestFlagsBroadcast;
            }

            if (args.callback is string callback)
            {
                data.callback = callback;
            } else if (args.callback is CallbackObj obj) {
                data.callback = obj.url;
                if (obj.backgroundBit)
                {
                    data.flags |= AbiConstants.RequestFlagsBackground;
                }
            } else {
                data.callback = "";
            }

            data.info = new List<InfoPair>();
            if (args.info is Dictionary<string, string> dictionary) {
                foreach (var info in dictionary)
                {
                    data.info.Add(new InfoPair()
                    {
                        key = info.Key,
                        value = info.Value
                    });
                }
            }

            SigningRequest req = new SigningRequest( 
                Constants.ProtocolVersion,
                data,
                options.zlib,
                null,//options.abiProvider
                null
            );

            // sign the request if given a signature provider
            if (options.signatureProvider != null)
            {
                req.sign(options.signatureProvider);
            }

            return req;*/
        }

        /**
 * Synchronously create a new signing request.
 * @throws If an un-encoded action with no abi def is encountered.
 */
        public static async Task<SigningRequest> createSync(SigningRequestCreateArguments args, SigningRequestEncodingOptions options = null, Dictionary<string, Abi> abis = null)
        {
            var version = 2;
            SigningRequestData data = new SigningRequestData();
            //            Action<object> encode = new Action<object>((object action) => encodeAction(action, abis));

            async Task<EosSharp.Core.Api.v1.Action> encode(EosSharp.Core.Api.v1.Action action)
            {
                EosApi eosApi = new EosApi(new EosConfigurator(), new HttpHandler());    // TODO Unity-Specific HttpHandler

                var abi = (await eosApi.GetAbi(new GetAbiRequest() { account_name = action.account }, true)).abi;
                AbiSerializationProvider abiSerializationProvider = new AbiSerializationProvider(eosApi);
                action.data = abiSerializationProvider.SerializeActionData(action, abi);    // TODO hm. weird way ... 
                return action;
            }

            // multi-chain requests requires version 3
            if (args.chainId == null)
            {
                version = 3;
            }

            // set the request data
            if (args.identity != null) {
                if (args.identity.scope != null)
                {
                    version = 3;
                }
                data.req = new Tuple<string, object>("identity", args.identity);
                // TODO            data.req = ['identity', this.identityType(version).from(args.identity)]
            }
            else if (args.action != null && args.actions == null && args.transaction == null)
            {
                data.req = new Tuple<string, object>("action", await encode(args.action));
            }
            else if (args.actions != null && args.action == null && args.transaction == null)
            {
                if (args.actions.Length == 1)
                {
                    data.req = new Tuple<string, object>("action", await encode(args.actions[0]));
                }
                else
                {
                    // TODO                 data.req = ['action[]', args.actions.map(encode)]
                    data.req = new Tuple<string, object>("actions", args.actions.Select(async action => await encode(action)).Select(t => t.Result).ToArray());
                }
            }
            // set the request data


            else if (args.transaction != null && args.action == null && args.actions == null)
            {
                var tx = args.transaction;
                // set default values if missing
                if (tx.expiration == null)
                {
                    tx.expiration = new DateTime(1970, 1, 1);
                }

                if (tx.ref_block_num == null)
                {
                    tx.ref_block_num = 0;
                }

                if (tx.ref_block_prefix == null)
                {
                    tx.ref_block_prefix = 0;
                }

                if (tx.context_free_actions == null)
                {
                    tx.context_free_actions = new List<EosSharp.Core.Api.v1.Action>();
                }

                if (tx.transaction_extensions == null)
                {
                    tx.transaction_extensions = new List<EosSharp.Core.Api.v1.Extension>();
                }

                if (tx.delay_sec == null)
                {
                    tx.delay_sec = 0;
                }

                if (tx.max_cpu_usage_ms == null)
                {
                    tx.max_cpu_usage_ms = 0;
                }

                if (tx.max_net_usage_words == null)
                {
                    tx.max_net_usage_words = 0;
                }

                // encode actions if needed
                tx.actions = tx.actions.Select(async action => await encode(action)).Select(t => t.Result).ToList();
                data.req = new Tuple<string, object>("transaction", tx);
            }
            else
            {
                throw new Exception("Invalid arguments: Must have exactly one of action, actions or transaction");
            }


// TODO
            // set the chain id
//                if (args.chainId === null)
//                {
//                    data.chain_id = ChainIdVariant.from(['chain_alias', 0])
//                }
//                else
//                {
//                    data.chain_id = ChainId.from(args.chainId || ChainName.EOS).chainVariant
//                }


            // set the chain id
            data.chain_id = Constants.variantId(args.chainId);
            data.flags = new RequestFlags(AbiConstants.RequestFlagsNone);

            data.flags.broadcast = (args.broadcast ?? data.req.Item1 != "identity");
            if (args.callback is string callback)
            {
                data.callback = callback;
            }
            else if (args.callback is CallbackObj obj)
            {
                data.callback = obj.url;
                if (obj.background)
                {
                    data.flags.background = (obj.background || false);
                }
            }
            else
            {
                data.callback = "";
            }

            // info pairs
            data.info = new List<InfoPair>();
            if (args.info is Dictionary<string, string> dictionary)
            {
                foreach (var info in dictionary)
                {
                    data.info.Add(new InfoPair()
                    {
                        key = info.Key,
                        value = info.Value
                    });
                }
            }

            if (args.chainIds != null && args.chainIds.Length > 0 && args.chainId == null)
            {
//                    const ids = args.chainIds.map((id) => ChainId.from(id).chainVariant)
                var ids = args.chainIds.Select((id) => id);
                data.info.Add(new InfoPair()
                {
                    key = "chain_ids",
                    value = "" // Serializer.encode({ object: ids, type: { type: ChainIdVariant, array: true} }),
                });
            }

            SigningRequest req = new SigningRequest(
                Constants.ProtocolVersion,
                data,
                options.zlib,
                options.abiProvider, //options.abiProvider
                null
            );

            // sign the request if given a signature provider
            if (options.signatureProvider != null)
            {
                req.sign(options.signatureProvider);
            }

            // sign the request if given a signature provider
            if (options.signatureProvider != null)
            {
                req.sign(options.signatureProvider);
            }

            return req;
        }


        /** Creates an identity request. */
        public static async Task<SigningRequest> identity(SigningRequestCreateIdentityArguments args, SigningRequestEncodingOptions options)
        {
            EosSharp.Core.Api.v1.PermissionLevel permission = new EosSharp.Core.Api.v1.PermissionLevel()
            {
                actor = args.account ?? Constants.PlaceholderName,
                permission = args.permission ?? Constants.PlaceholderPermission
            };

            if (permission.actor == Constants.PlaceholderName && permission.permission == Constants.PlaceholderPermission)
            {
                permission = null;
            }

            return await create(new SigningRequestCreateArguments()
            {
                identity = new Identity(){ permission = permission },
                broadcast = false,
                callback = args.callback,
                info = args.info
            }, options);
        }

        /**
         * Create a request from a chain id and serialized transaction.
         * @param chainId The chain id where the transaction is valid.
         * @param serializedTransaction The serialized transaction.
         * @param options Creation options.
         */
        public static SigningRequest fromTransaction(object chainId /*Uint8Array | string*/, 
            object serializedTransaction /*Uint8Array | string*/, 
            SigningRequestEncodingOptions options) 
        {
            if (chainId is byte[] byteId)
            {
                chainId = SerializationHelper.ByteArrayToHexString(byteId);
            }
            if (serializedTransaction is string transaction)
            {
                serializedTransaction = SerializationHelper.HexStringToByteArray(transaction);
            }

            using (MemoryStream buf = new MemoryStream())
            {
                buf.WriteByte(2); // header
                var id= Constants.variantId(chainId);
                if (id.Item1 == "chain_alias")
                {
                    buf.WriteByte(0);
                    buf.WriteByte(Convert.ToByte((int)id.Item2));
                }
                else
                {
                    buf.WriteByte(1);
                    byte[] bytes = SerializationHelper.HexStringToByteArray((string)id.Item2);
                    buf.Write(bytes, 0, bytes.Length);
                }

                buf.WriteByte(2); // transaction variant
                buf.Write((byte[])serializedTransaction,0, ((byte[])serializedTransaction).Length);
                buf.WriteByte(AbiConstants.RequestFlagsBroadcast); // flags
                buf.WriteByte(0); // callback
                buf.WriteByte(0); // info

                return fromData(buf.ToArray(), options);
            }
        }

        /** Creates a signing request from encoded `esr:` uri string. */
        public static SigningRequest from(string uri, SigningRequestEncodingOptions options) {
            //const [scheme, path] = uri.split(':')
            string[] subs = uri.Split(':');
            string scheme = subs[0];
            string path = subs[1];
            if (scheme != "esr" && scheme != "web+esr")
            {
                throw new Exception("Invalid scheme");
            }

            byte[] data = Convert.FromBase64String(path.StartsWith("//") ? path.Substring(2) : path);
            return fromData(data, options);
        }

        public static SigningRequest fromData(byte[] data, SigningRequestEncodingOptions options ) {
            byte header  = data[0];
            byte version = (byte)(header & ~(1 << 7));
            if (version != Constants.ProtocolVersion)
            {
                throw new Exception("Unsupported protocol version");
            }

            byte[] array = new byte[data.Length-1]; 
            data.CopyTo(array, 1);
            
            if ((header & (1 << 7)) != 0)
            {
                if (options.zlib == null)
                {
                    throw new Exception("Compressed URI needs zlib");
                }

                array = options.zlib.inflateRaw(array);
            }


            // TODO !

            var req = new SigningRequestData();
            var signature = new RequestSignature();

/*            var req = type.deserialize(buffer); // array to buffer
            var signature = new RequestSignature();

            if (buffer.haveReadData())
            {
                const type = AbiTypes.get("request_signature")!;
                signature = type.deserialize(buffer);
            }*/

            return new SigningRequest(
                version,
                req,
                options.zlib,
                options.abiProvider,
                signature
            );
        }

        /** The signing request version. */
        public byte version;

        /** The raw signing request data. */
        public SigningRequestData data;

        /** The request signature. */
        public RequestSignature signature;

        private IZlibProvider zlib;
        private IAbiProvider abiProvider;

            /**
             * Create a new signing request.
             * Normally not used directly, see the `create` and `from` class methods.
             */
        public SigningRequest(byte version, 
            SigningRequestData data,
            IZlibProvider zlib,
            IAbiProvider abiProvider,
            RequestSignature signature
        ) 
        {

            if (data.flags.broadcast && data.req.Item1 == "identity")
            {
                throw new Exception("Invalid request (identity request cannot be broadcastBit)");
            }

            this.version = version;
            this.data = data;
            this.zlib = zlib;
            this.abiProvider = abiProvider;
            this.signature = signature;
        }

        /**
         * Sign the request, mutating.
         * @param signatureProvider The signature provider that provides a signature for the signer.
         */
        public void sign(ISignatureProvider signatureProvider)
        {
            byte[] message = getSignatureDigest();
            signature = signatureProvider.sign(SerializationHelper.ByteArrayToHexString(message));
        }

        /**
         * Get the signature digest for this request.
         */
        public byte[] getSignatureDigest()
        {

            // TODO, is the following correct?

            // protocol version + utf8 "request"
            byte[] versionUtf8 = {this.version, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74};
            byte[] data = getData();

            byte[] req = new byte[versionUtf8.Length + data.Length];
            versionUtf8.CopyTo(req, 0);
            data.CopyTo(req, versionUtf8.Length);
            return Sha256Manager.GetHash(req);
        }

        /**
         * Set the signature data for this request, mutating.
         * @param signer Account name of signer.
         * @param signature The signature string.
         */
        public void setSignature(string signer, string signature)
        {
            this.signature = new RequestSignature()
            {
                signer = signer,
                signature = signature
            };
        }

        /**
         * Set the request callback, mutating.
         * @param url Where the callback should be sent.
         * @param backgroundBit Whether the callback should be sent in the backgroundBit.
         */
        public void setCallback(string url, bool background)
        {
            this.data.callback = url;
            this.data.flags.background = background;
        }

        /**
         * Set broadcastBit flag.
         * @param broadcastBit Whether the transaction should be broadcastBit by receiver.
         */
        public void setBroadcast(bool broadcast)
        {
            this.data.flags.broadcast = broadcast;
        }

        /*
         * Encode this request into an `esr:` uri.
         * @argument compress Whether to compress the request data using zlib,
         *                    defaults to true if omitted and zlib is present;
         *                    otherwise false.
         * @argument slashes Whether add slashes after the protocol scheme, i.e. `esr://`.
         *                   Defaults to true.
         * @returns An esr uri string.
         */
        public string encode(bool? compress = null, bool? slashes = null)
        {
            bool shouldCompress = compress ?? this.zlib != null;
            if (shouldCompress && this.zlib == null)
            {
                throw new Exception("Need zlib to compress");
            }

            var header = this.version;
            byte[] data = getData();
            byte[] sigData = getSignatureData();
            byte[] array = new byte[data.Length + sigData.Length];
            data.CopyTo(array,0);
            sigData.CopyTo(array, data.Length);
/*            if (shouldCompress)
            {
                const deflated = zlib!.deflateRaw(array);
                if (array.Length > deflated.byteLength)
                {
                    header |= 1 << 7
                    array = deflated
                }
            }*/

            byte[] @out = new byte[1 + array.Length];
            @out[0] = header;
            array.CopyTo(@out, 1);
            string scheme = "esr:";
            if (slashes != false)
            {
                scheme += "//";
            }

            return scheme + Convert.ToBase64String(@out);
        }

        /** Get the request data without header or signature. */
        public byte[] getData()
        {
            // TODO
            /*type.serialize(buffer, data);
            return buffer.asUint8Array();*/
            return new byte[]{};
    }

        /** Get signature data, returns an empty array if request is not signed. */
        public byte[] getSignatureData() {
            if (signature == null)
            {
                return new byte[0];
            }

            return new byte[]{};
            // TODO
/*            const type = AbiTypes.get("request_signature")!;
            type.serialize(buffer, signature);
            return buffer.asUint8Array();*/
        }

        /** ABI definitions required to resolve request. */
        public List<string> getRequiredAbis()
        {
            return getRawActions().Where(a => !Constants.isIdentity(a)).Select(a => a.account).ToList();

/*            return this.getRawActions()
                .filter((action) => !Constants.isIdentity(action))
                .map((action) => action.account)
                .filter((value, index, self) => self.indexOf(value) == index)*/
        }

        /** Whether TaPoS values are required to resolve request. */
        public bool requiresTapos()
        {
            var tx = getRawTransaction();
            return !isIdentity() && !Constants.hasTapos(tx);
        }

        /** Resolve required ABI definitions. */
        public async Task<AbiMap> fetchAbis(IAbiProvider abiProvider)
        {
            var provider = abiProvider != null ? abiProvider : this.abiProvider;
            if (provider == null)
            {
                throw new Exception("Missing ABI provider");
            }

            var abis = new Dictionary<string, Abi>();
            foreach (var account in getRequiredAbis())
            {
                abis.Add(account, await provider.GetAbi(account));
            }
            return abis;
        }

        /**
         * Decode raw actions actions to object representations.
         * @param abis ABI defenitions required to decode all actions.
         * @param signer Placeholders in actions will be resolved to signer if set.
         */
        public ResolvedAction[] resolveActions(AbiMap abis, EosSharp.Core.Api.v1.PermissionLevel signer)
        {
            return getRawActions().Select(rawAction =>
            {
                Abi contractAbi = null; //: any | undefined
                if (Constants.isIdentity(rawAction))
                {
                    contractAbi = EosioSigningRequestAbiData.Data;
                }
                else
                {
                    contractAbi = abis.SingleOrDefault(abi => abi.Key == rawAction.account).Value;
                }

                if (contractAbi == null)
                {
                    throw new Exception($"Missing ABI definition for {rawAction.account}");
                }

/*                if (signer != null)
                {
                    // hook into eosjs name decoder and return the signing account if we encounter the placeholder
                    // this is fine because getContract re-creates the initial types each time
                    contractAbi.types.get("name")!.deserialize = (buffer: Serialize.SerialBuffer) => {
                        string name = buffer.getName();
                        if (name == Constants.PlaceholderName)
                        {
                            return signer.actor;
                        }
                        else if (name == Constants.PlaceholderPermission)
                        {
                            return signer.permission;
                        }
                        else
                        {
                            return name;
                        }
                    }
                }*/

                EosSharp.Core.Api.v1.Action action = new EosSharp.Core.Api.v1.Action()
                {
                    data = rawAction.data,
                    account = rawAction.account,
                    authorization = rawAction.authorization,
                    name = rawAction.name,
                    hex_data = rawAction.hex_data
                };
                if (signer != null)
                {
                    action.authorization = action.authorization.Select(auth =>
                    {
                        string actor = auth.actor;
                        string permission = auth.permission;
                        if (actor == Constants.PlaceholderName)
                        {
                            actor = signer.actor;
                        }

                        if (permission == Constants.PlaceholderPermission)
                        {
                            permission = signer.permission;
                        }

                        // backwards compatibility, actor placeholder will also resolve to permission when used in auth
                        if (permission == Constants.PlaceholderName)
                        {
                            permission = signer.permission;
                        }

                        return new EosSharp.Core.Api.v1.PermissionLevel()
                        {
                            actor = actor,
                            permission = permission
                        };
                    }).ToList();
                }

                return new ResolvedAction()
                {
                    authorization = action.authorization.ToArray(),
                    name = action.name,
                    account = action.account
                };
            }).ToArray();
        }

        public ResolvedTransaction resolveTransaction(AbiMap abis, EosSharp.Core.Api.v1.PermissionLevel signer, TransactionContext ctx)
        {

            TransactionHeader serializeTransactionHeader(TransactionContext ctx, uint expire_seconds)
            {

                uint prefix = 1;//SerializationHelper.ReverseHex(ctx.) -- parseInt(reverseHex(refBlock.id.substr(16, 8)), 16);

                TransactionHeader transactionHeader = new TransactionHeader()
                {
                    expiration = ctx.timestamp.Value.AddSeconds(expire_seconds),
                    ref_block_num = Convert.ToUInt16(ctx.ref_block_num & 0xffff),
                    ref_block_prefix = prefix
                };
                return transactionHeader;
            }

            var tx = getRawTransaction();
            if (!isIdentity() && !Constants.hasTapos(tx))
            {
                if (ctx.expiration != null && ctx.ref_block_num != null && ctx.ref_block_prefix != null)
                {
                    tx.expiration = ctx.expiration.Value;// TODO !!!
                    tx.ref_block_num = Convert.ToUInt16(ctx.ref_block_num.Value);
                    tx.ref_block_prefix = ctx.ref_block_prefix.Value;
                }
                else if (ctx.block_num != null && ctx.ref_block_prefix != null && ctx.timestamp != null)
                {
                    var header  = serializeTransactionHeader(ctx, ctx.expire_seconds ?? 60);
                    tx.expiration = header.expiration.Value;
                    tx.ref_block_num = Convert.ToUInt16(header.ref_block_num.Value);
                    tx.ref_block_prefix = header.ref_block_prefix.Value;
                }
                else
                {
                    throw new Exception("Invalid transaction context, need either a reference block or explicit TAPoS values");
                }
            }
            else if (this.isIdentity() && this.version > 2)
            {
                // From ESR version 3 all identity requests have expiration
                tx.expiration = ctx.expiration ?? new DateTime();// TODO ?? expirationTime(ctx.timestamp, ctx.expire_seconds)
            }

            var actions  = this.resolveActions(abis, signer);

            return new ResolvedTransaction()
            {
                actions = actions,
                context_free_actions = new ResolvedAction[0],
                delay_sec = tx.delay_sec ?? 0,
                expiration = tx.expiration,
                max_cpu_usage_ms = tx.max_cpu_usage_ms ?? 0,
                max_net_usage_words = tx.max_cpu_usage_ms ?? 0,
                ref_block_num = tx.ref_block_num ?? 0,
                ref_block_prefix = tx.ref_block_prefix ?? 0,
                transaction_extensions = new object[0]
            };
        }

        public async Task<ResolvedSigningRequest> resolve(AbiMap abis, EosSharp.Core.Api.v1.PermissionLevel signer, TransactionContext ctx) {
            var tx = resolveTransaction(abis, signer, ctx);

            List<Action> actions = tx.actions.Select(action =>
            {
                Abi abi = null;
                if (isIdentity(action))
                {
//                    abi = (this.constructor as typeof SigningRequest).identityAbi(this.version)
                }
                else
                {
                    abi = abis[action.account];
                }

                if (abi == null)
                {
                    throw new Exception($"Missing ABI definition for {action.account}");
                }

//                const type  = abi.getActionType(action.name)!
//                const data  = Serializer.encode({ object: action.data, type, abi })
                return new Action() { }; //.from({ ...action, data})
            }).ToList();

            var transaction = new Transaction()
            {
                actions = actions,
                max_cpu_usage_ms = tx.max_cpu_usage_ms,
                delay_sec = tx.delay_sec,
                expiration = tx.expiration,
                max_net_usage_words = tx.max_net_usage_words,
                ref_block_num = tx.ref_block_num,
                ref_block_prefix = tx.ref_block_prefix
            };

            string chainId;
/*            if (this.isMultiChain())
            {
                if (!ctx.chainId)
                {
                    throw new Error('Missing chosen chain ID for multi-chain request')
                }
                chainId = ChainId.from(ctx.chainId)
                const ids = this.getChainIds()
                if (ids && !ids.some((id) => chainId.equals(id)))
                {
                    throw new Error('Trying to resolve for chain ID not defined in request')
                }
            }
            else
            {*/
            chainId = this.getChainId();
            //}


            byte[] serializedTransaction = { };
            // TODO, overload SerializePackedTransaction with ABI-List
            if (abiProvider is AbiSerializationProvider) 
                serializedTransaction = await ((AbiSerializationProvider)abiProvider).SerializePackedTransaction(transaction);
            return new ResolvedSigningRequest(this, signer, transaction, tx, chainId);
        }

        /**
         * Get the id of the chain where this request is valid.
         * @returns The 32-byte chain id as hex encoded string.
         */
        public ChainId getChainId() {
            var id= data.chain_id;
            switch (id.Item1)
            {
                case "chain_id":
                    return (string)id.Item2;
                case "chain_alias":
                    if (Constants.ChainIdLookup.ContainsKey((ChainName)id.Item2))
                    {
                        return Constants.ChainIdLookup[(ChainName)id.Item2];
                    }
                    else
                    {
                        throw new Exception("Unknown chain id alias");
                    }
                default:
                    throw new Exception("Invalid signing request data");
            }
        }

        /** Return the actions in this request with action data encoded. */
        public EosSharp.Core.Api.v1.Action[] getRawActions()
        {
            var req = this.data.req;
            switch (req.Item1)
            {
                case "action":
                    return new[] {(EosSharp.Core.Api.v1.Action)req.Item2};
                case "action[]":
                    return (EosSharp.Core.Api.v1.Action[]) req.Item2;
                case "identity":
                    string data = "0101000000000000000200000000000000"; // placeholder permission
                    EosSharp.Core.Api.v1.PermissionLevel authorization = Constants.PlaceholderAuth;
                    if (((Identity)req.Item2).permission != null)
                    {
                        // TODO
                        /*idType.serialize(buf, req.Item2);
                        data = SerializationHelper.ByteArrayToHexString(buf.asUint8Array());*/

                        AbiSerializationProvider s = new AbiSerializationProvider(null);    // TODO
                        // TODO serialize identity-request-type?
                        data = SerializationHelper.ByteArrayToHexString(new byte[] { });

                        authorization = ((Identity) req.Item2).permission;
                    }

                    return new[]
                    {
                        new EosSharp.Core.Api.v1.Action()
                        {
                            account = "",
                            name = "identity",
                            authorization = new List<EosSharp.Core.Api.v1.PermissionLevel>(){authorization},
                            hex_data = data // TODO data or hex_data?
                        },
                    };
                case "transaction":
                    return ((EosSharp.Core.Api.v1.Transaction)req.Item2).actions.ToArray();
                default:
                    throw new Exception("Invalid signing request data");
            }
        }

        /** Unresolved transaction. */
        public EosSharp.Core.Api.v1.Transaction getRawTransaction() {
            var req  = data.req;
            switch (req.Item1)
            {
                case "transaction":
                    return (EosSharp.Core.Api.v1.Transaction)req.Item2;
                case "action":
                case "action[]":
                case "identity":
                    return new EosSharp.Core.Api.v1.Transaction()
                    {
                        actions = getRawActions().ToList(),
                        context_free_actions = new List<EosSharp.Core.Api.v1.Action>(),
                        transaction_extensions = new List<EosSharp.Core.Api.v1.Extension>(),
                        expiration = new DateTime(1970, 1, 1),
                        ref_block_num = 0,
                        ref_block_prefix = 0,
                        max_cpu_usage_ms = 0,
                        max_net_usage_words = 0,
                        delay_sec = 0
                    };
                default:
                    throw new Exception("Invalid signing request data");
            }
        }

        /** Whether the request is an identity request. */
        public bool isIdentity()
        {
            return data.req.Item1 == "identity";
        }

        bool isIdentity(Action action)
        {
            string account = action.account;
            string name = action.name;
            return /*account.rawValue.equals(0) &&*/ name.Equals("identity");
        }

        bool isIdentity(ResolvedAction action)
        {
            string account = action.account;
            string name = action.name;
            return /*account.rawValue.equals(0) &&*/ name.Equals("identity");
        }

        /** Whether the request should be broadcastBit by signer. */
        public bool shouldBroadcast()
        {
            return !isIdentity() && data.flags.broadcast;
        }

        /**
         * Present if the request is an identity request and requests a specific account.
         * @note This returns `nil` unless a specific identity has been requested,
         *       use `isIdentity` to check id requests.
         */
        public string getIdentity() {
            if (data.req.Item1 == "identity" && ((Identity)data.req.Item2).permission != null)
            {
                string actor = ((Identity)data.req.Item2).permission.actor;
                return actor == Constants.PlaceholderName ? null : actor;
            }
            return null;
        }

        /**
     * Present if the request is an identity request and requests a specific permission.
     * @note This returns `nil` unless a specific permission has been requested,
     *       use `isIdentity` to check id requests.
     */
        public string getIdentityPermission() {
            if (data.req.Item1 == "identity" && ((Identity)data.req.Item2).permission != null)
            {
                string permission = ((Identity)data.req.Item2).permission.permission;
                return permission == Constants.PlaceholderName ? null : permission;
            }
            return null;
        }

        /** Get raw info dict */
        public Dictionary<string, byte[]> getRawInfo()
        {
//            let rv: {[key: string]: Uint8Array } = { }
            var rv = new Dictionary<string, byte[]>();

            foreach (var infoPair in data.info)
            {
                rv.Add(infoPair.key, infoPair.value is string value ? SerializationHelper.HexStringToByteArray(value) : (byte[])infoPair.value);
            }
            return rv;
        }

        /** Get metadata values as strings. */
        public Dictionary<string, string>  getInfo()
        {
            var rv = new Dictionary<string, string>();
            var raw = getRawInfo();

            foreach (var rawInfo in raw)
            {
                rv.Add(rawInfo.Key, SerializationHelper.ByteArrayToHexString(rawInfo.Value));
            }

            return rv;
        }

        /** Set a metadata key. */
        public void setInfoKey(string key, object value /* string | boolean*/)
        {

            var pair = data.info.SingleOrDefault(i => i.key == key); 
            
            byte[] encodedValue;
            switch (value) {
                case string stringtype:
                    encodedValue = Encoding.UTF8.GetBytes(stringtype);  // TODO UTF-8 ?
                break;
                case bool booltype:
                    encodedValue = new byte[] {Convert.ToByte(booltype ? 1 : 0)};
                    break;
                default:
                    throw new Exception("Invalid value type, expected string or boolean.");
            }
            if (pair == null)
            {
                pair = new InfoPair()
                {
                    key = key,
                    value = encodedValue
                };
                data.info.Add(pair);
            }
            else
            {
                // TODO replace pair
                pair.value = encodedValue;
            }
        }

        /** Return a deep copy of this request. */
        public SigningRequest clone() {
            RequestSignature signature = null;
            if (this.signature != null)
            {
                signature = JsonConvert.DeserializeObject<RequestSignature>(
                    JsonConvert.SerializeObject(this.signature));
            }

            SigningRequestData data = null;
            if (this.data != null)
            {
                data = JsonConvert.DeserializeObject<SigningRequestData>(
                    JsonConvert.SerializeObject(this.data));
            }

            return new SigningRequest(
                version,
                data,
                zlib,
                abiProvider,
                signature
            );
        }

        /**
         * Present if the request is an identity request and requests a specific permission.
         * @note This returns `nil` unless a specific permission has been requested,
         *       use `isIdentity` to check id requests.
         */
        public string getIdentityScope() {
            if (!this.isIdentity() || this.version <= 2)
            {
                return null;
            }
            var id = this.data.req.Item2 as Identity;
            return id.scope;
        }

    // Convenience methods.

    /*public string toString()
    {
        return this.encode();
    }

    public object toJSON()  // TODO
    {
        return this.encode();
    }*/
}

    public class ResolvedSigningRequest
    {
        /** Recreate a resolved request from a callback payload. */
        public static async Task<ResolvedSigningRequest> fromPayload(CallbackPayload payload, SigningRequestEncodingOptions options, IAbiProvider abiProvider) {
            SigningRequest request = SigningRequest.from(payload.req, options);
            var abis = await request.fetchAbis(abiProvider);
            return await request.resolve(
                abis,
                new EosSharp.Core.Api.v1.PermissionLevel()
                {
                    actor = payload.sa,
                    permission = payload.sp
                },
                new TransactionContext()
                {
                    ref_block_num = Convert.ToUInt16(payload.rbn),
                    ref_block_prefix = Convert.ToUInt16(payload.rid),
                    expiration = Convert.ToDateTime(payload.ex)
                }
            );
        }

        /** The request that created the transaction. */
        public readonly SigningRequest request;
        /** Expected signer of transaction. */
        public readonly EosSharp.Core.Api.v1.PermissionLevel signer;
        /** Transaction object with action data encoded. */
        public readonly EosSharp.Core.Api.v1.Transaction transaction;
        /** Transaction object with action data decoded. */
        public readonly ResolvedTransaction resolvedTransaction;
        /** Id of chain where the request was resolved. */
        public readonly ChainId chainId;

        public ResolvedSigningRequest(SigningRequest request, EosSharp.Core.Api.v1.PermissionLevel signer, EosSharp.Core.Api.v1.Transaction transaction, ResolvedTransaction resolvedTransaction, string chainId)
        {
            this.request = request;
            this.signer = signer;
            this.transaction = transaction;
            this.resolvedTransaction = resolvedTransaction;
            this.chainId = chainId;
        }

        public ResolvedCallback getCallback(string[] signatures, int? blockNum)
        {

            string callback = request.data.callback;
            RequestFlags flags = request.data.flags;

            if (string.IsNullOrEmpty(callback))
            {
                return null;
            }

            if (signatures == null || signatures.Length == 0)
            {
                throw new Exception("Must have at least one signature to resolve callback");
            }

            CallbackPayload payload = new CallbackPayload()
            {
                sig = signatures[0],
                //tx = getTransactionId(),
                rbn = transaction.ref_block_num.ToString(),
                rid = transaction.ref_block_prefix.ToString(),
                ex = transaction.expiration,
                req = request.encode(),
                sa = signer.actor,
                sp = signer.permission,
            };
            /*for ( const [ n, sig] of signatures.slice(1).entries()) {
                payload[`sig${ n }`] = sig
            }*/
            if (blockNum != null)
            {
                payload.bn = blockNum.ToString();
            }

            Regex regex = new Regex(@"({{([a-z0-9]+)}})");
            string url = regex.Replace(callback, "");

            return new ResolvedCallback()
            {
                background = flags.background,
                payload = payload,
                url = url
            };
        }

        public IdentityProof getIdentityProof(SignatureType signature)
        {
            if (!this.request.isIdentity())
            {
                throw new Exception("Not a identity request");
            }

            return new IdentityProof()
            {
                chainId = this.chainId,
                scope = this.request.getIdentityScope()!,
                expiration = this.transaction.expiration,
                signer = this.signer,
                signature = signature as string
            };
        }
    }

    /** Internal helper that creates a contract representation from an abi for the eosjs serializer. */
    /*function getContract(contractAbi: any): Serialize.Contract {
        const types = Serialize.getTypesFromAbi(Serialize.createInitialTypes(), contractAbi)
        const actions = new Map<string, Serialize.Type>()
        for (const {name, type} of contractAbi.actions) {
            actions.set(name, Serialize.getType(types, type))
        }
        return {types, actions}
    }

    async function serializeAction(
        action: abi.Action,
        textEncoder: TextEncoder,
        textDecoder: TextDecoder,
        abiProvider?: AbiProvider
    ) {
        if (typeof action.data === 'string') {
            return action
        }
        let contractAbi: any
        if (isIdentity(action)) {
            contractAbi = abi.data
        } else if (abiProvider) {
            contractAbi = await abiProvider.getAbi(action.account)
        } else {
            throw new Error('Missing abi provider')
        }
        const contract = getContract(contractAbi)
        return Serialize.serializeAction(
            contract,
            action.account,
            action.name,
            action.authorization,
            action.data,
            textEncoder,
            textDecoder
        )
    }

    function variantId(chainId?: abi.ChainId | abi.ChainAlias): abi.VariantId {
        if (!chainId) {
            chainId = ChainName.EOS
        }
        if (typeof chainId === 'number') {
            return ['chain_alias', chainId]
        } else {
            // resolve known chain id's to their aliases
            const name = idToName(chainId)
            if (name !== ChainName.UNKNOWN) {
                return ['chain_alias', name]
            }
            return ['chain_id', chainId]
        }
    }

    function isIdentity(action: abi.Action) {
        return action.account === '' && action.name === 'identity'
    }

    function hasTapos(tx: abi.Transaction) {
        return !(
            tx.expiration === '1970-01-01T00:00:00.000' &&
            tx.ref_block_num === 0 &&
            tx.ref_block_prefix === 0
        )
    }*/

    /** Resolve a chain id to a chain name alias, returns UNKNOWN (0x00) if the chain id has no alias. */
    /*export function idToName(chainId: abi.ChainId): ChainName {
        chainId = chainId.toLowerCase()
        for (const [n, id] of ChainIdLookup) {
            if (id === chainId) {
                n
            }
        }
        return ChainName.UNKNOWN
    }*/

    /** Resolve a chain name alias to a chain id. */
    /*export function nameToId(chainName: ChainName): abi.ChainId {
        return (
            ChainIdLookup.get(chainName) ||
            '0000000000000000000000000000000000000000000000000000000000000000'
        )
    }*/

    public class ResolvedTransaction
    {
        /** The time at which a transaction expires. */
        public DateTime expiration;
        /** *Specifies a block num in the last 2^16 blocks. */
        public ushort ref_block_num;
        /** Specifies the lower 32 bits of the block id. */
        public uint ref_block_prefix;
        /** Upper limit on total network bandwidth (in 8 byte words) billed for this transaction. */
        public uint max_net_usage_words;
        /** Upper limit on the total CPU time billed for this transaction. */
        public byte max_cpu_usage_ms;
        /** Number of seconds to delay this transaction for during which it may be canceled. */
        public uint delay_sec;
        /** The context free actions in the transaction. */
        public ResolvedAction[] context_free_actions;
        /** The actions in the transaction. */
        public ResolvedAction[] actions;
        /** Transaction extensions. */
        public object[] transaction_extensions;
    }

    public class ResolvedAction
    {
        /** The account (a.k.a. contract) to run action on. */
        public string account;
        /** The name of the action. */
        public string name;
        /** The permissions authorizing the action. */
        public PermissionLevel[] authorization;
        /** The decoded action data. */
        public Dictionary<string, object> data;
    }
}