/*
 * Copyright (C) 2015 Tirasa (info@tirasa.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;

namespace LdapForNet.Adsddl.data
{
    /// <summary>
    ///     An unsigned 8-bit value that specifies the revision of the ACL. The only two legitimate forms of ACLs supported for
    ///     on-the-wire management or manipulation are type 2 and type 4. No other form is valid for manipulation on the wire.
    ///     Therefore this field MUST be set to one of the following values.
    ///     <see href="https://msdn.microsoft.com/en-us/library/cc230297.aspx">cc230297</see>
    /// </summary>
    public enum AclRevision : byte
    {
        /// <summary>
        ///     Unknown.
        /// </summary>
        Unexpected = 0x00,

        /// <summary>
        ///     0x02 - When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, and 0x11 can be present in the ACL. An AceType of
        ///     0x11 is used for SACLs but not for DACLs.
        /// </summary>
        AclRevision = 0x02,

        /// <summary>
        ///     0x04 - When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed. ACLs of revision 0x04 are
        ///     applicable only to directory service objects. An AceType of 0x11 is used for SACLs but not for DACLs.
        /// </summary>
        AclRevisionDs = 0x04
    }

    public static class AclRevisionExtension
    {
        /// <summary>
        ///     Parse byte value.
        ///     @param value byet value.
        ///     @return ACL revision.
        /// </summary>
        public static AclRevision ParseValue(byte value)
        {
            foreach (AclRevision type in Enum.GetValues(typeof(AclRevision)))
            {
                if ((byte) type == value)
                {
                    return type;
                }
            }

            return AclRevision.Unexpected;
        }
    }
}