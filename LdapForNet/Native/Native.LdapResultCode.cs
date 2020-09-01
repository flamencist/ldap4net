﻿// ReSharper disable InconsistentNaming

namespace LdapForNet.Native
{
    public static partial class Native
    {
        public enum ResultCode
        {
            LDAP_NOT_SUPPORTED = -12,
            LDAP_PARAM_ERROR = -9,
            Success = 0,
            OperationsError = 1,
            ProtocolError = 2,
            TimeLimitExceeded = 3,
            SizeLimitExceeded = 4,
            CompareFalse = 5,
            CompareTrue = 6,
            AuthMethodNotSupported = 7,
            StrongAuthRequired = 8,
            ReferralV2 = 9,
            Referral = 10,
            AdminLimitExceeded = 11,
            UnavailableCriticalExtension = 12,
            ConfidentialityRequired = 13,
            SaslBindInProgress = 14,
            NoSuchAttribute = 16,
            UndefinedAttributeType = 17,
            InappropriateMatching = 18,
            ConstraintViolation = 19,
            AttributeOrValueExists = 20,
            InvalidAttributeSyntax = 21,
            NoSuchObject = 32,
            AliasProblem = 33,
            InvalidDNSyntax = 34,
            AliasDereferencingProblem = 36,
            InappropriateAuthentication = 48,
            InvalidCredentials = 49,
            InsufficientAccessRights = 50,
            Busy = 51,
            Unavailable = 52,
            UnwillingToPerform = 53,
            LoopDetect = 54,
            SortControlMissing = 60,
            OffsetRangeError = 61,
            NamingViolation = 64,
            ObjectClassViolation = 65,
            NotAllowedOnNonLeaf = 66,
            NotAllowedOnRdn = 67,
            EntryAlreadyExists = 68,
            ObjectClassModificationsProhibited = 69,
            ResultsTooLarge = 70,
            AffectsMultipleDsas = 71,
            VirtualListViewError = 76,
            Other = 80
        }
    }
}