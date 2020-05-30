using System;

namespace LdapForNet
{
    /// <summary>
    ///     Used https://docs.microsoft.com/ru-ru/windows/security/threat-protection/auditing/event-4720
    /// </summary>
    /// ReSharper disable InconsistentNaming
    [Flags]
    public enum UserAccountControl
    {
        /// <summary>
        ///     Empty
        /// </summary>
        NONE = 0,

        /// <summary>
        ///     The logon script is executed.
        /// </summary>
        SCRIPT = 1,

        /// <summary>
        ///     The user account is disabled.
        /// </summary>
        ACCOUNTDISABLE = 2,

        /// <summary>
        ///     This flag is undeclared.
        /// </summary>
        Undeclared = 4,

        /// <summary>
        ///     The home directory is required.
        /// </summary>
        HOMEDIR_REQUIRED = 8,

        /// <summary>
        ///     LOCKOUT
        /// </summary>
        LOCKOUT = 16,

        /// <summary>
        ///     No password is required.
        /// </summary>
        PASSWD_NOTREQD = 32,

        /// <summary>
        ///     The user cannot change the password. This is a permission on the user's object.
        /// </summary>
        PASSWD_CANT_CHANGE = 64,

        /// <summary>
        ///     The user can send an encrypted password.
        ///     Can be set using “Store password using reversible encryption” checkbox.
        /// </summary>
        ENCRYPTED_TEXT_PWD_ALLOWED = 128,

        /// <summary>
        ///     This is an account for users whose primary account is in another domain.
        ///     This account provides user access to this domain, but not to any domain that trusts this domain.
        ///     This is sometimes referred to as a local user account.
        /// </summary>
        TEMP_DUPLICATE_ACCOUNT = 256,

        /// <summary>
        ///     This is a default account type that represents a typical user.
        /// </summary>
        NORMAL_ACCOUNT = 512,

        /// <summary>
        ///     This is a permit to trust an account for a system domain that trusts other domains.
        /// </summary>
        INTERDOMAIN_TRUST_ACCOUNT = 2048,

        /// <summary>
        ///     This is a computer account for a computer that is running Microsoft Windows NT 4.0 Workstation,
        ///     Microsoft Windows NT 4.0 Server, Microsoft Windows 2000 Professional,
        ///     or Windows 2000 Server and is a member of this domain.
        /// </summary>
        WORKSTATION_TRUST_ACCOUNT = 4096,

        /// <summary>
        ///     This is a computer account for a domain controller that is a member of this domain.
        /// </summary>
        SERVER_TRUST_ACCOUNT = 8192,

        /// <summary>
        ///     Represents the password, which should never expire on the account.
        ///     Can be set using “Password never expires” checkbox.
        /// </summary>
        DONT_EXPIRE_PASSWORD = 65536,

        /// <summary>
        ///     This is an MNS logon account.
        /// </summary>
        MNS_LOGON_ACCOUNT = 131072,

        /// <summary>
        ///     When this flag is set, it forces the user to log on by using a smart card.
        /// </summary>
        SMARTCARD_REQUIRED = 262144,

        /// <summary>
        ///     When this flag is set, the service account (the user or computer account) under which a service runs is trusted for
        ///     Kerberos delegation.
        ///     Any such service can impersonate a client requesting the service.
        ///     To enable a service for Kerberos delegation, you must set this flag on the userAccountControl property of the
        ///     service account.
        ///     If you enable Kerberos constraint or unconstraint delegation or disable these types of delegation in Delegation tab
        ///     you will get this flag changed.
        /// </summary>
        TRUSTED_FOR_DELEGATION = 524288,

        /// <summary>
        ///     When this flag is set, the security context of the user is not delegated to a service even if the service account
        ///     is set as trusted for Kerberos delegation.
        ///     Can be set using “Account is sensitive and cannot be delegated” checkbox.
        /// </summary>
        NOT_DELEGATED = 1048576,

        /// <summary>
        ///     (Windows 2000/Windows Server 2003)
        ///     Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.
        ///     Can be set using “Use Kerberos DES encryption types for this account” checkbox.
        /// </summary>
        USE_DES_KEY_ONLY = 2097152,

        /// <summary>
        ///     (Windows 2000/Windows Server 2003)
        ///     This account does not require Kerberos pre-authentication for logging on.
        ///     Can be set using “Do not require Kerberos preauthentication” checkbox.
        /// </summary>
        DONT_REQ_PREAUTH = 4194304,

        /// <summary>
        ///     (Windows 2000/Windows Server 2003)
        ///     The user's password has expired.
        /// </summary>
        PASSWORD_EXPIRED = 8388608,

        /// <summary>
        ///     (Windows 2000/Windows Server 2003)
        ///     The account is enabled for delegation.
        ///     This is a security-sensitive setting. Accounts that have this option enabled should be tightly controlled.
        ///     This setting lets a service that runs under the account assume a client's identity and authenticate as that user to
        ///     other remote servers on the network.
        ///     If you enable Kerberos protocol transition delegation or disable this type of delegation in Delegation tab you will
        ///     get this flag changed.
        /// </summary>
        TRUSTED_TO_AUTH_FOR_DELEGATION = 16777216,

        /// <summary>
        ///     The account is a read-only domain controller (RODC).
        ///     This is a security-sensitive setting.
        ///     Removing this setting from an RODC compromises security on that server.
        /// </summary>
        PARTIAL_SECRETS_ACCOUNT = 67108864
    }

    public static class UserAccountControlExtension
    {
        #region Flags Extensions

        public static bool Has(this UserAccountControl flags, UserAccountControl flag) => (flags & flag) == flag;

        public static bool HasAny(this UserAccountControl flags, UserAccountControl flag) => (flags & flag) != 0;

        public static bool HasNot(this UserAccountControl flags, UserAccountControl flag) => (flags & flag) == 0;

        #endregion
    }
}