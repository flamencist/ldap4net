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
using System.Collections.Generic;
using System.Linq;

namespace LdapForNet.Adsddl.data
{
    /// <summary>
    ///     An ACCESS_MASK that specifies the user rights allowed by this ACE.
    ///     <see href="https://msdn.microsoft.com/en-us/library/cc230289.aspx">cc230289</see>
    /// </summary>
    public class AceRights
    {
        /// <summary>
        ///     Standard ACE rights.
        /// </summary>
        public enum ObjectRight : uint
        {
            /// <summary>
            ///     GENERIC_READ - When read access to an object is requested, this bit is translated to a combination of bits.
            ///     These are most often set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
            ///     specify a different configuration.) The bits that are set are implementation dependent. During this
            ///     translation, the GR bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
            ///     checked against the ACE structures in the security descriptor that attached to the object.
            ///     When the GR bit is set in an ACE that is to be attached to an object, it is translated into a combination of
            ///     bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
            ///     specify a different configuration.) The bits that are set are implementation dependent. During this
            ///     translation, the GR bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
            ///     granted by this ACE.
            /// </summary>
            GR = 0x80000000,

            /// <summary>
            ///     GENERIC_WRITE - When write access to an object is requested, this bit is translated to a combination of bits,
            ///     which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
            ///     specify a different configuration.) The bits that are set are implementation dependent. During this
            ///     translation, the GW bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
            ///     checked against the ACE structures in the security descriptor that attached to the object.
            ///     When the GW bit is set in an ACE that is to be
            ///     attached to an object, it is translated into a combination of bits, which are usually set in the lower 16
            ///     bits of the ACCESS_MASK. (Individual protocol specifications MAY specify a different configuration.) The bits
            ///     that are set are implementation dependent. During this translation, the GW bit is cleared. The resulting
            ///     ACCESS_MASK bits are the actual permissions that are granted by this ACE.
            /// </summary>
            GW = 0x40000000,

            /// <summary>
            ///     GENERIC_EXECUTE - When execute access to an object is requested, this bit is translated to a combination of
            ///     bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
            ///     specify a different configuration.) The bits that are set are implementation dependent. During this
            ///     translation, the GX bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
            ///     checked against the ACE structures in the security descriptor that attached to the object.
            ///     When the GX bit is set in an ACE that is to be attached to an object, it is translated into a combination of
            ///     bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
            ///     specify a different configuration.) The bits that are set are implementation dependent. During this
            ///     translation, the GX bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
            ///     granted by this ACE.
            /// </summary>
            GX = 0x20000000,

            /// <summary>
            ///     GENERIC_ALL - When all access permissions to an object are requested, this bit is translated to a combination
            ///     of bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications
            ///     MAY specify a different configuration.) Objects are free to include bits from the upper 16 bits in that
            ///     translation as required by the objects semantics. The bits that are set are implementation dependent. During
            ///     this translation, the GA bit is cleared. The resulting ACCESS_MASK bits are the actual permissions that are
            ///     checked against the ACE structures in the security descriptor that attached to the object.
            ///     When the GA bit is set in an ACE that is to be attached to an object, it is translated into a combination of
            ///     bits, which are usually set in the lower 16 bits of the ACCESS_MASK. (Individual protocol specifications MAY
            ///     specify a different configuration.) Objects are free to include bits from the upper 16 bits in that
            ///     translation, if required by the objects semantics. The bits that are set are implementation dependent.
            ///     During this translation, the GA bit is cleared. The resulting ACCESS_MASK bits are the actual permissions
            ///     that are granted by this ACE.
            /// </summary>
            GA = 0x10000000,

            /// <summary>
            ///     MAXIMUM_ALLOWED - When requested, this bit grants the requestor the maximum permissions allowed to the
            ///     object through the Access Check Algorithm. This bit can only be requested; it cannot be set in an ACE.
            ///     Specifying the Maximum Allowed bit in the SECURITY_DESCRIPTOR has no meaning. The MA bit SHOULD NOT be set
            ///     and SHOULD be ignored when part of a SECURITY_DESCRIPTOR structure.
            /// </summary>
            MA = 0x02000000,

            /// <summary>
            ///     ACCESS_SYSTEM_SECURITY - When requested, this bit grants the requestor the maximum permissions allowed to the
            ///     object through the Access Check Algorithm. This bit can only be requested; it cannot be set in an ACE.
            ///     Specifying the Maximum Allowed bit in the SECURITY_DESCRIPTOR has no meaning. The MA bit SHOULD NOT be set
            ///     and SHOULD be ignored when part of a SECURITY_DESCRIPTOR structure.
            /// </summary>
            AS = 0x01000000,

            /// <summary>
            ///     SYNCHRONIZE - Specifies access to the object sufficient to synchronize or wait on the object.
            /// </summary>
            SY = 0x00100000,

            /// <summary>
            ///     WRITE_OWNER - Specifies access to change the owner of the object as listed in the security descriptor.
            /// </summary>
            WO = 0x00080000,

            /// <summary>
            ///     WRITE_DACL - Specifies access to change the discretionary access control list of the security descriptor of
            ///     an object.
            /// </summary>
            WD = 0x00040000,

            /// <summary>
            ///     READ_CONTROL - Specifies access to read the security descriptor of an object.
            /// </summary>
            RC = 0x00020000,

            /// <summary>
            ///     DELETE - Specifies access to delete an object.
            /// </summary>
            SD = 0x00010000,

            /// <summary>
            ///     ADS_RIGHT_DS_CONTROL_ACCESS - The ObjectType GUID identifies an extended access right.
            /// </summary>
            CR = 0x00000100,

            /// <summary>
            ///     ADS_RIGHT_DS_WRITE_PROP - The ObjectType GUID identifies a property set or property of the object.
            ///     The ACE controls the trustee's right to write the property or property set.
            /// </summary>
            WP = 0x00000020

            // FA(0x001F01FF),
            // FX(0x001200A0),
            // FW(0x00100116),
            // FR(0x00120089),
            // KA(0x00000019),
            // KR(0x0000003F),
            // KX(0x00000019),
            // KW(0x00000006),
            // LO(0x00000080),
            // DT(0x00000040),
            // RP(0x00000010),
            // SW(0x00000008),
            // LC(0x00000004),
            // DC(0x00000002),
            // CC(0x00000001);
        }

        /// <summary>
        ///     Standard ACE rights.
        /// </summary>
        private readonly List<ObjectRight> rights = new List<ObjectRight>();

        /// <summary>
        ///     Custom/Other rights.
        /// </summary>
        private long others;

        /// <summary>
        ///     Parse ACE rights.
        ///     @param value int value representing rights.
        ///     @return ACE rights.
        /// </summary>
        public static AceRights parseValue(int value)
        {
            AceRights res = new AceRights();
            if (value == 0)
            {
                return res;
            }

            res.others = value;

            foreach (ObjectRight type in Enum.GetValues(typeof(ObjectRight)))
            {
                if ((value & (int) type) == (int) type)
                {
                    res.rights.Add(type);
                    res.others ^= (int) type;
                }
            }

            return res;
        }

        /// <summary>
        ///     Gets custom/other rights.
        ///     @return custom/other rights.
        /// </summary>
        public long getOthers() => this.others;

        /// <summary>
        ///     Sets custom/other rights.
        ///     @param others custom/other rights.
        ///     @return the current ACE rights.
        /// </summary>
        public AceRights setOthers(long others)
        {
            this.others = others;
            return this;
        }

        /// <summary>
        ///     Gets standard ACE rights.
        ///     @return standard ACE rights.
        /// </summary>
        public List<ObjectRight> getObjectRights() => this.rights;

        /// <summary>
        ///     Adds standard ACE right.
        ///     @param right Object right.
        ///     @return the carrent ACE rights.
        /// </summary>
        public AceRights addOjectRight(ObjectRight right)
        {
            this.rights.Add(right);
            return this;
        }

        /// <summary>
        ///     Gets rights as unsigned int.
        ///     @return rights as unsigned int.
        /// </summary>
        public long asUInt() => this.rights.Aggregate(this.others, (current, right) => current + (int) right);
    }
}