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

namespace LdapForNet.Adsddl.data
{
    /// <summary>
    ///     An unsigned 8-bit integer that specifies a set of ACE type-specific control flags.
    ///     <see href="https://msdn.microsoft.com/en-us/library/cc230296.aspx">cc230296</see>
    /// </summary>
    public enum AceFlag
    {
        /// <summary>
        ///     0x00 - None used
        /// </summary>
        NONE = 0x00,
        
        /// <summary>
        ///     0x02 - Child objects that are containers, such as directories, inherit the ACE as an effective ACE. The inherited
        ///     ACE is inheritable unless the NO_PROPAGATE_INHERIT_ACE bit flag is also set.
        /// </summary>
        CONTAINER_INHERIT_ACE = 0x02,

        /// <summary>
        ///     0x80 - Used with system-audit ACEs in a system access control list (SACL) to generate audit messages for failed
        ///     access attempts.
        /// </summary>
        FAILED_ACCESS_ACE_FLAG = 0x80,

        /// <summary>
        ///     0x08 - Indicates an inherit-only ACE, which does not control access to the object to which it is attached. If
        ///     this flag is not set, the ACE is an effective ACE that controls access to the object to which it is attached.
        ///     Both effective and inherit-only ACEs can be inherited depending on the state of the other inheritance flags.
        /// </summary>
        INHERIT_ONLY_ACE = 0x08,

        /// <summary>
        ///     0x10 - Indicates that the ACE was inherited. The system sets this bit when it propagates an inherited ACE to a
        ///     child object.
        /// </summary>
        INHERITED_ACE = 0x10,

        /// <summary>
        ///     0x04 - If the ACE is inherited by a child object, the system clears the OBJECT_INHERIT_ACE and
        ///     CONTAINER_INHERIT_ACE flags in the inherited ACE. This prevents the ACE from being inherited by subsequent
        ///     generations of objects.
        /// </summary>
        NO_PROPAGATE_INHERIT_ACE = 0x04,

        /// <summary>
        ///     0x01 - Noncontainer child objects inherit the ACE as an effective ACE.
        ///     For child objects that are containers, the ACE is inherited as an inherit-only ACE unless the
        ///     NO_PROPAGATE_INHERIT_ACE bit flag is also set.
        /// </summary>
        OBJECT_INHERIT_ACE = 0x01,

        /// <summary>
        ///     0x40 - Used with system-audit ACEs in a SACL to generate audit messages for successful access attempts.
        /// </summary>
        SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
    }

    public static class AceFlagExtension
    {
        public static string GetString(this AceFlag flag)
        {
            switch (flag)
            {
                case AceFlag.CONTAINER_INHERIT_ACE:
                    return "CI";
                case AceFlag.FAILED_ACCESS_ACE_FLAG:
                    return "FA";
                case AceFlag.INHERIT_ONLY_ACE:
                    return "IO";
                case AceFlag.INHERITED_ACE:
                    return "ID";
                case AceFlag.NO_PROPAGATE_INHERIT_ACE:
                    return "NP";
                case AceFlag.OBJECT_INHERIT_ACE:
                    return "OI";
                case AceFlag.SUCCESSFUL_ACCESS_ACE_FLAG:
                    return "SA";
                case AceFlag.NONE:
                    return string.Empty;
                default:
                    return flag.ToString();
            }
        }

        /// <summary>
        ///     Parse byte value.
        ///     @param value byte value.
        ///     @return ACE flags.
        /// </summary>
        public static List<AceFlag> parseValue(byte value)
        {
            var res = new List<AceFlag>();

            foreach (AceFlag type in Enum.GetValues(typeof(AceFlag)))
            {
                if ((value & (byte) type) == (byte) type)
                {
                    res.Add(type);
                }
            }

            return res;
        }
    }
}