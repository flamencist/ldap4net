// ReSharper disable InconsistentNaming
namespace LdapForNet.Native
{
    public static partial class Native
    {
        /// <summary>
        /// LDAP_OPTions
        /// 0x0000 - 0x0fff reserved for api options
        /// 0x1000 - 0x3fff reserved for api extended options
        /// 0x4000 - 0x7fff reserved for private and experimental options
        /// </summary>
        public enum LdapOption
        {
            LDAP_OPT_API_INFO = 0x0000,
            LDAP_OPT_DESC = 0x0001, /* historic */
            LDAP_OPT_DEREF = 0x0002,
            LDAP_OPT_SIZELIMIT = 0x0003,
            LDAP_OPT_TIMELIMIT = 0x0004,

            /* 0x05 - 0x07 not defined */
            LDAP_OPT_REFERRALS = 0x0008,
            LDAP_OPT_RESTART = 0x0009,

            /* 0x0a - 0x10 not defined */
            LDAP_OPT_PROTOCOL_VERSION = 0x0011,
            LDAP_OPT_SERVER_CONTROLS = 0x0012,
            LDAP_OPT_CLIENT_CONTROLS = 0x0013,

            /* 0x14 not defined */
            LDAP_OPT_API_FEATURE_INFO = 0x0015,
            LDAP_OPT_SSL = 0x0a,

            /* 0x16 - 0x2f not defined */
            LDAP_OPT_HOST_NAME = 0x0030,
            LDAP_OPT_RESULT_CODE = 0x0031,
            LDAP_OPT_ERROR_NUMBER = LDAP_OPT_RESULT_CODE,
            LDAP_OPT_DIAGNOSTIC_MESSAGE = 0x0032,
            LDAP_OPT_ERROR_STRING = LDAP_OPT_DIAGNOSTIC_MESSAGE,
            LDAP_OPT_MATCHED_DN = 0x0033,

            LDAP_OPT_CLIENT_CERTIFICATE = 0x80,
            LDAP_OPT_SERVER_CERTIFICATE = 0x81,

            /* 0x0034 - 0x3fff not defined */
            /* 0x0091 used by Microsoft for LDAP_OPT_AUTO_RECONNECT */
            LDAP_OPT_SSPI_FLAGS = 0x0092,

            /* 0x0093 used by Microsoft for LDAP_OPT_SSL_INFO */
            /* 0x0094 used by Microsoft for LDAP_OPT_REF_DEREF_CONN_PER_MSG */
            LDAP_OPT_SIGN = 0x0095,
            LDAP_OPT_ENCRYPT = 0x0096,
            LDAP_OPT_SASL_METHOD = 0x0097,

            /* 0x0098 used by Microsoft for LDAP_OPT_AREC_EXCLUSIVE */
            LDAP_OPT_SECURITY_CONTEXT = 0x0099,

            /* 0x009A used by Microsoft for LDAP_OPT_ROOTDSE_CACHE */
            /* 0x009B - 0x3fff not defined */
            /* API Extensions */
            LDAP_OPT_API_EXTENSION_BASE = 0x4000, /* API extensions */

            /* private and experimental options */
            /* OpenLDAP specific options */
            LDAP_OPT_DEBUG_LEVEL = 0x5001, /* debug level */
            LDAP_OPT_TIMEOUT = 0x5002, /* default timeout */
            LDAP_OPT_REFHOPLIMIT = 0x5003, /* ref hop limit */
            LDAP_OPT_NETWORK_TIMEOUT = 0x5005, /* socket level timeout */
            LDAP_OPT_URI = 0x5006,
            LDAP_OPT_REFERRAL_URLS = 0x5007, /* Referral URLs */
            LDAP_OPT_SOCKBUF = 0x5008, /* sockbuf */
            LDAP_OPT_DEFBASE = 0x5009, /* searchbase */
            LDAP_OPT_CONNECT_ASYNC = 0x5010, /* create connections asynchronously */
            LDAP_OPT_CONNECT_CB = 0x5011, /* connection callbacks */
            LDAP_OPT_SESSION_REFCNT = 0x5012, /* session reference count */

            /* OpenLDAP TLS options */
            LDAP_OPT_X_TLS = 0x6000,
            LDAP_OPT_X_TLS_CTX = 0x6001, /* OpenSSL CTX* */
            LDAP_OPT_X_TLS_CACERTFILE = 0x6002,
            LDAP_OPT_X_TLS_CACERTDIR = 0x6003,
            LDAP_OPT_X_TLS_CERTFILE = 0x6004,
            LDAP_OPT_X_TLS_KEYFILE = 0x6005,
            LDAP_OPT_X_TLS_REQUIRE_CERT = 0x6006,
            LDAP_OPT_X_TLS_PROTOCOL_MIN = 0x6007,
            LDAP_OPT_X_TLS_CIPHER_SUITE = 0x6008,
            LDAP_OPT_X_TLS_RANDOM_FILE = 0x6009,
            LDAP_OPT_X_TLS_SSL_CTX = 0x600a, /* OpenSSL SSL* */
            LDAP_OPT_X_TLS_CRLCHECK = 0x600b,
            LDAP_OPT_X_TLS_CONNECT_CB = 0x600c,
            LDAP_OPT_X_TLS_CONNECT_ARG = 0x600d,
            LDAP_OPT_X_TLS_DHFILE = 0x600e,
            LDAP_OPT_X_TLS_NEWCTX = 0x600f,
            LDAP_OPT_X_TLS_CRLFILE = 0x6010, /* GNUtls only */
            LDAP_OPT_X_TLS_PACKAGE = 0x6011,
            LDAP_OPT_X_TLS_CERT	= 0x6017,
            LDAP_OPT_X_TLS_KEY = 0x6018,
            LDAP_OPT_X_TLS_NEVER = 0,
            LDAP_OPT_X_TLS_HARD = 1,
            LDAP_OPT_X_TLS_DEMAND = 2,
            LDAP_OPT_X_TLS_ALLOW = 3,
            LDAP_OPT_X_TLS_TRY = 4,
            LDAP_OPT_X_TLS_CRL_NONE = 0,
            LDAP_OPT_X_TLS_CRL_PEER = 1,
            LDAP_OPT_X_TLS_CRL_ALL = 2,

            ///* OpenLDAP SASL options */
            LDAP_OPT_X_SASL_MECH = 0x6100,
            LDAP_OPT_X_SASL_REALM = 0x6101,
            LDAP_OPT_X_SASL_AUTHCID = 0x6102,
            LDAP_OPT_X_SASL_AUTHZID = 0x6103,
            LDAP_OPT_X_SASL_SSF = 0x6104, /* read-only */
            LDAP_OPT_X_SASL_SSF_EXTERNAL = 0x6105, /* write-only */
            LDAP_OPT_X_SASL_SECPROPS = 0x6106, /* write-only */
            LDAP_OPT_X_SASL_SSF_MIN = 0x6107,
            LDAP_OPT_X_SASL_SSF_MAX = 0x6108,
            LDAP_OPT_X_SASL_MAXBUFSIZE = 0x6109,
            LDAP_OPT_X_SASL_MECHLIST = 0x610a, /* read-only */
            LDAP_OPT_X_SASL_NOCANON = 0x610b,
            LDAP_OPT_X_SASL_USERNAME = 0x610c, /* read-only */
            LDAP_OPT_X_SASL_GSS_CREDS = 0x610d,

            /* OpenLDAP GSSAPI options */
            LDAP_OPT_X_GSSAPI_DO_NOT_FREE_CONTEXT = 0x6200,
            LDAP_OPT_X_GSSAPI_ALLOW_REMOTE_PRINCIPAL = 0x6201,

            /*
             * OpenLDAP per connection tcp-keepalive settings
             * (Linux only, ignored where unsupported)
             */
            LDAP_OPT_X_KEEPALIVE_IDLE = 0x6300,
            LDAP_OPT_X_KEEPALIVE_PROBES = 0x6301,
            LDAP_OPT_X_KEEPALIVE_INTERVAL = 0x6302,

            /* Private API Extensions -- reserved for application use */
            LDAP_OPT_PRIVATE_EXTENSION_BASE = 0x7000, /* Private API inclusive */

            /*
             * ldap_get_option() and ldap_set_option() return values.
             * As later versions may return other values indicating
             * failure, current applications should only compare returned
             * value against LDAP_OPT_SUCCESS.
             */
            LDAP_OPT_SUCCESS = 0,
            LDAP_OPT_ERROR = -1
        }
    }
}