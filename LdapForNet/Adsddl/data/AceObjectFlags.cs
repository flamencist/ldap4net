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
    /**
     * A 32-bit unsigned integer that specifies a set of bit flags that indicate whether the ObjectType and
     * InheritedObjectType fields contain valid data. This parameter can be one or more of the following values.
     *
     * <see href="https://msdn.microsoft.com/en-us/library/cc230289.aspx">cc230289</see>
     */
    public class AceObjectFlags
    {
        /// <summary>
        /// ACE object flag.
        /// </summary>
        [Flags]
        public enum Flag
        {
            /// <summary>
            /// 0x00000001 - ObjectType is valid.
            /// </summary>
            ACE_OBJECT_TYPE_PRESENT = 0x00000001,

            /// <summary>
            /// 0x00000002 - InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.
            /// </summary>
            ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002
        }

        /// <summary>
        /// Standard flags.
        /// </summary>
        private HashSet<Flag> flags = new HashSet<Flag>();

        /// <summary>
        /// Custom/Other flags.
        /// </summary>
        private int others = 0;

        public AceObjectFlags(params Flag[] fls)
        {
            if (fls.Length == 0)
            {
                return;
            }

            foreach (Flag flag in fls)
            {
                if (!flags.Contains(flag))
                {
                    flags.Add(flag);
                }
            }
        }

        /// <summary>
        ///  Parse flags given as int value.
        /// </summary>
        /// <param name="value">value flags given as int value.</param>
        /// <returns>ACE object flags.</returns>
        public static AceObjectFlags parseValue(int value)
        {
            AceObjectFlags res = new AceObjectFlags();

            res.others = value;

            foreach (Flag type in Enum.GetValues(typeof(Flag)))
            {
                if ((value & (int)type) == (int)type)
                {
                    res.flags.Add(type);
                    res.others ^= (int)type;
                }
            }

            return res;
        }

        /// <summary>
        /// Gets standard ACE object flags.
        /// 
        /// @return stabdatd ACE object flags.
        /// </summary>
        public HashSet<Flag> getFlags() => flags;

        /// <summary>
        /// Adds standard ACE object flag.
        /// 
        /// @param flag standard ACE object flag.
        /// @return the current ACE object flags.
        /// </summary>
        public AceObjectFlags addFlag(Flag flag)
        {
            if (!flags.Contains(flag))
            {
                flags.Add(flag);
            }

            return this;
        }

        /// <summary>
        /// Gets custom/other ACE object flags.
        /// 
        /// @return custom/other ACE object flags as long value.
        /// </summary>
        public long getOthers() => others;

        /// <summary>
        /// Sets custom/others ACE object flags.
        /// 
        /// @param others custom/other ACE object flags given as int value..
        /// @return the current ACE object flags.
        /// </summary>
        public AceObjectFlags setOthers(int others)
        {
            this.others = others;
            return this;
        }

        /// <summary>
        /// Gets custom/other ACE object flags as long value.
        /// 
        /// @return custom/other ACE object flags as long value.
        /// </summary>
        public long asUInt() => this.flags.Aggregate<Flag, long>(this.others, (current, flag) => current + (long) flag);
    }

    public static class FlagExtensions
    {
        public static bool Has(this AceObjectFlags.Flag flags, AceObjectFlags.Flag flag) => (flags & flag) == flag;

        public static AceObjectFlags.Flag SetFlag(this AceObjectFlags.Flag flags, AceObjectFlags.Flag flag, bool value)
        {
            if (value)
            {
                flags |= flag;
            }
            else
            {
                flags &= ~flag;
            }
            return flags;
        }
        
        public static bool HasAny(this AceObjectFlags.Flag flags, AceObjectFlags.Flag flag) => (flags & flag) != 0;

        public static bool HasNot(this AceObjectFlags.Flag flags, AceObjectFlags.Flag flag) => (flags & flag) == 0;
    }
}