/** SigningRequest ABI and typedefs. */

using System;
using System.Collections.Generic;
using EosSharp.Core.Api.v1;
using Newtonsoft.Json;
using AccountName = System.String; /*name*/
using VariantId = System.Tuple<string, object>;
using VariantReq = System.Tuple<string, object>;
using RequestFlags = System.Int32;  //number;  // TODO

namespace EosioSigningRequest
{
    public static class AbiConstants
    {
        public static byte RequestFlagsNone = 0;
        public static byte RequestFlagsBroadcast = 1 << 0;
        public static byte RequestFlagsBackground = 1 << 1;
    }

    public class TransactionHeader
    {
        [JsonProperty("expiration")] public DateTime? expiration; /*time_point_sec*/ // TODO

        [JsonProperty("ref_block_num")] public ushort? ref_block_num; /*uint16*/

        [JsonProperty("ref_block_prefix")] public uint? ref_block_prefix; /*uint32*/

        [JsonProperty("max_net_usage_words")] public uint? max_net_usage_words; /*varuint32*/

        [JsonProperty("max_cpu_usage_ms")] public byte? max_cpu_usage_ms; /*uint8*/

        [JsonProperty("delay_sec")] public uint? delay_sec; /*varuint32*/
    }

    public class SigningRequestData
    {
        [JsonProperty("chain_id")] public VariantId chain_id;

        [JsonProperty("req")] public VariantReq req;

        [JsonProperty("flags")] public RequestFlags flags;

        [JsonProperty("callback")] public string callback;

        [JsonProperty("info")] public List<InfoPair> info;
    }

    public class InfoPair
    {
        [JsonProperty("key")] public string key;

        [JsonProperty("value")] public object value; // = Uint8Array | string /*bytes*/ 
    }

    public class Identity
    {
        [JsonProperty("permission")] public EosSharp.Core.Api.v1.PermissionLevel permission; // | undefined | null
        [JsonProperty("scope")] public string scope;
    }

    public class RequestSignature
    {
        [JsonProperty("signer")] public AccountName signer;

        [JsonProperty("signature")] public string signature;
    }

    static class EosioSigningRequestAbiData
    {
        public static readonly Abi Data = new Abi()
        {
            version = "eosio = =abi/1.1",
            types = new List<AbiType>
            {
                new AbiType()
                {
                    new_type_name = "account_name",
                    type = "name",
                },
                new AbiType()
                {
                    new_type_name = "action_name",
                    type = "name",
                },
                new AbiType()
                {
                    new_type_name = "permission_name",
                    type = "name",
                },
                new AbiType()
                {
                    new_type_name = "chain_alias",
                    type = "uint8",
                },
                new AbiType()
                {
                    new_type_name = "chain_id",
                    type = "checksum256",
                },
                new AbiType()
                {
                    new_type_name = "request_flags",
                    type = "uint8",
                }
            },
            structs = new List<AbiStruct>()
            {
                new AbiStruct()
                {
                    name = "permission_level",
                    fields = new List<AbiField>()
                    {
                        new AbiField()
                        {
                            name = "actor",
                            type = "account_name",
                        },
                        new AbiField()
                        {
                            name = "permission",
                            type = "permission_name",
                        }
                    }
                },
                new AbiStruct()
                {
                    name = "action",
                    fields = new List<AbiField>()
                    {
                        new AbiField()
                        {
                            name = "account",
                            type = "account_name",
                        },
                        new AbiField()
                        {
                            name = "name",
                            type = "action_name",
                        },
                        new AbiField()
                        {
                            name = "authorization",
                            type = "permission_level[]",
                        },
                        new AbiField()
                        {
                            name = "data",
                            type = "bytes",
                        }
                    },
                },
                new AbiStruct()
                {
                    name = "extension",
                    fields = new List<AbiField>()
                    {
                        new AbiField()
                        {
                            name = "type",
                            type = "uint16",
                        },
                        new AbiField()
                        {
                            name = "data",
                            type = "bytes",
                        }
                    }
                },
                new AbiStruct()
                {
                    name = "transaction_header",
                    fields = new List<AbiField>()
                    {
                        new AbiField()
                        {
                            name = "expiration",
                            type = "time_point_sec",
                        },
                        new AbiField()
                        {
                            name = "ref_block_num",
                            type = "uint16",
                        },
                        new AbiField()
                        {
                            name = "ref_block_prefix",
                            type = "uint32",
                        },
                        new AbiField()
                        {
                            name = "max_net_usage_words",
                            type = "varuint32",
                        },
                        new AbiField()
                        {
                            name = "max_cpu_usage_ms",
                            type = "uint8",
                        },
                        new AbiField()
                        {
                            name = "delay_sec",
                            type = "varuint32",
                        }
                    }
                },
                new AbiStruct()
                {
                    name = "transaction",
                    @base = "transaction_header",
                    fields = new List<AbiField>
                    {
                        new AbiField()
                        {
                            name = "context_free_actions",
                            type = "action[]",
                        },
                        new AbiField()
                        {
                            name = "actions",
                            type = "action[]",
                        },
                        new AbiField()
                        {
                            name = "transaction_extensions",
                            type = "extension[]",
                        }
                    },
                },
                new AbiStruct()
                {
                    name = "info_pair",
                    fields = new List<AbiField>()
                    {
                        new AbiField()
                        {
                            name = "key",
                            type = "string",
                        },
                        new AbiField()
                        {
                            name = "value",
                            type = "bytes",
                        }
                    }
                },
                new AbiStruct()
                {
                    name = "signing_request",
                    fields = new List<AbiField>
                    {
                        new AbiField()
                        {
                            name = "chain_id",
                            type = "variant_id",
                        },
                        new AbiField()
                        {
                            name = "req",
                            type = "variant_req",
                        },
                        new AbiField()
                        {
                            name = "flags",
                            type = "request_flags",
                        },
                        new AbiField()
                        {
                            name = "callback",
                            type = "string",
                        },
                        new AbiField()
                        {
                            name = "info",
                            type = "info_pair[]",
                        }
                    }
                },
                new AbiStruct()
                {
                    name = "identity",
                    fields = new List<AbiField>()
                    {
                        new AbiField()
                        {
                            name = "permission",
                            type = "permission_level?",
                        },
                    },
                },
                new AbiStruct()
                {
                    name = "request_signature",
                    fields = new List<AbiField>()
                    {
                        new AbiField()
                        {
                            name = "signer",
                            type = "name",
                        },
                        new AbiField()
                        {
                            name = "signature",
                            type = "signature",
                        },
                    }
                }
            },
            variants = new List<Variant>()
            {
                new Variant()
                {
                    name = "variant_id",
                    types = new List<string>() {"chain_alias", "chain_id"},
                },
                new Variant()
                {
                    name = "variant_req",
                    types = new List<string> {"action", "action[]", "transaction", "identity"},
                },
            },
            actions = new List<AbiAction>()
            {
                new AbiAction()
                {
                    name = "identity",
                    type = "identity",
                }
            }
        };
    }

    public class RequestFlags
    {
        private byte value;

        private static byte broadcastBit = 1 << 0;
        private static byte backgroundBit = 1 << 1;

        public bool broadcast
        {
            get => getbroadcast();
            set => setbroadcast(value);
        }

        public bool background
        {
            get => getbackground();
            set => setbackground(value);
        }

        public RequestFlags(byte requestFlagsNone)
        {
            this.value = requestFlagsNone;
        }

        private bool getbroadcast()
        {
            return (this.value & RequestFlags.broadcastBit) != 0;
        }

        private void setbroadcast(bool enabled)
        {
            this.setFlag(RequestFlags.broadcastBit, enabled);
        }

        private bool getbackground()
        {
            return (this.value & RequestFlags.backgroundBit) != 0;
        }

        private void setbackground(bool enabled)
        {
            this.setFlag(RequestFlags.backgroundBit, enabled);
        }

        private void setFlag(byte flag, bool enabled)
        {
            if (enabled)
            {
                // TODO: implement bitwise operators in core, bn.js setbit does not work
                this.value = (byte) (this.value | flag);
            }
            else
            {
                if((this.value & flag) > 0)
                    this.value = (byte) (this.value ^ flag);    // TODO
//                this.value.imaskn(flag)
            }
        }
    }
}