namespace LdapForNet
{
    public static class LdapAttributes
    {
        //domain
        public const string Dc = "dc";
        public const string SubRefs = "subRefs";

        //common
        public const string Cn = "cn";
        public const string DistinguishedName = "distinguishedName";
        public const string Name = "name";
        public const string ObjectClass = "objectClass";
        public const string IpaUniqueID = "ipaUniqueID";
        public const string ObjectGuid = "objectGUID";
        public const string ObjectSid = "objectSid";
        public const string WhenChanged = "whenChanged";
        public const string ModifyTimestamp = "modifyTimestamp";

        //unit
        public const string Ou = "ou";
        public const string ManagedBy = "managedBy";

        //user
        public const string SAmAccountName = "sAMAccountName";
        public const string Sn = "sn";
        public const string Uid = "uid";
        public const string GivenName = "givenName";
        public const string MiddleName = "middleName";
        public const string DisplayName = "displayName";
        public const string Mail = "mail";
        public const string Fax = "facsimileTelephoneNumber";
        public const string Mobile = "mobile";
        public const string IpPhone = "IpPhone";
        public const string HomePhone = "homePhone";
        public const string TelephoneNumber = "telephoneNumber";
        public const string MemberOf = "memberOf";
        public const string Title = "title";
        public const string Manager = "manager";
        public const string UserAccountControl = "userAccountControl";
        public const string PrimaryGroupID = "primaryGroupID";
        public const string UserPrincipalName = "userPrincipalName";

        //group
        public const string Description = "description";
    }
}