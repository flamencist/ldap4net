/*
 * Copyright (C) 2018 VMware, Inc.
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
/*
 * Copyright © 2018 VMware, Inc. All Rights Reserved.
 *
 * COPYING PERMISSION STATEMENT
 * SPDX-License-Identifier: Apache-2.0
 */

using System;
using System.Linq;
using LdapForNet.Adsddl.data;

namespace LdapForNet.Adsddl.dacl
{
    /// <summary>
    ///     Represents an assertion that an code ACL must contain an ACE (Access Control Entry) which meets the
    ///     criteria within this class. The criteria are defined as properties of the ACE.
    ///     Special interpretation of the 'excluded flag': If this flag is specified, and an ACE contains this flag, the ACE
    ///     cannot be considered to fulfill the assertion.
    /// </summary>
    public class AceAssertion
    {
        /// <summary>
        ///     One or more AceObjectFlags. May be null.
        /// </summary>
        private readonly AceObjectFlags aceObjectFlags;

        /// <summary>
        ///     A single AceRight.
        /// </summary>
        private readonly AceRights aceRight;

        /// <summary>
        ///     Single AceFlag that stipulates an ACE must NOT contain it; may be null.
        /// </summary>
        private readonly AceFlag excludedFlag;

        /// <summary>
        ///     Inherited Object type GUID. Must be set if Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT is one of the
        ///     AceObjectFlags; otherwise null.
        /// </summary>
        private readonly string inheritedObjectType;

        /// <summary>
        ///     Object type GUID. Must be set if Flag.ACE_OBJECT_TYPE_PRESENT is one of the AceObjectFlags; otherwise null.
        /// </summary>
        private readonly string objectType;

        /// <summary>
        ///     Single AceFlag that stipulates an ACE must contain it; may be null.
        /// </summary>
        private readonly AceFlag requiredFlag;

        /// <summary>
        ///     AceAssertion constructor
        /// </summary>
        /// <param name="aceRight">
        ///     A single AceRight (e.g.: use AceRights.parseValue(0x00000004) if AceRights.ObjectRight enum does not contain
        ///     desired right.) MUST be specified.
        /// </param>
        /// <param name="aceObjFlags">One or more AceObjectFlags, may be null.</param>
        /// <param name="objectType">Object type GUID. Must be set if Flag.ACE_OBJECT_TYPE_PRESENT is in aceObjFlags</param>
        /// <param name="inheritedObjectType">
        ///     Inherited object type GUID. Must be set if Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT is in aceObjFlags
        /// </param>
        /// <param name="requiredFlag">Single AceFlag that stipulates an ACE must contain it; may be null.</param>
        /// <param name="excludedFlag">Single AceFlag that stipulates an ACE must NOT contain it; may be null.</param>
        public AceAssertion(AceRights aceRight, AceObjectFlags aceObjFlags, string objectType, string inheritedObjectType,
            AceFlag requiredFlag, AceFlag excludedFlag)
        {
            this.aceRight = aceRight;
            this.aceObjectFlags = aceObjFlags;
            this.objectType = objectType;
            this.inheritedObjectType = inheritedObjectType;
            this.requiredFlag = requiredFlag;
            this.excludedFlag = excludedFlag;
        }

        /// <summary>
        ///     Gets the AceRight specifying the right of this assertion.
        /// </summary>
        /// <returns>AceRight object</returns>
        public AceRights getAceRight() => this.aceRight;

        /// <summary>
        ///     Gets one or more of the assertion, may be null.
        /// </summary>
        /// <returns>AceObjectFlags object or null if none</returns>
        public AceObjectFlags getObjectFlags() => this.aceObjectFlags;

        /// <summary>
        ///     Gets the object type GUID. Present only if Flag.ACE_OBJECT_TYPE_PRESENT is in getObjectFlags
        /// </summary>
        /// <returns></returns>
        public string getObjectType() => this.objectType;

        /// <summary>
        ///     Gets the inherited object type GUID. Present only if Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT is in getObjectFlags
        /// </summary>
        /// <returns>Inherited object type GUID string or null if none</returns>
        public string getInheritedObjectType() => this.inheritedObjectType;

        /// <summary>
        ///     Gets single AceFlag that stipulates an ACE must contain it; may be null.
        ///     @return Gets required flag
        /// </summary>
        public AceFlag getRequiredFlag() => this.requiredFlag;

        /// <summary>
        ///     Gets single AceFlag that stipulates an ACE must NOT contain it; may be null.
        ///     @return gets excluded flag
        /// </summary>
        public AceFlag getExcludedFlag() => this.excludedFlag;

        public override int GetHashCode()
        {
            var prime = 31;
            var result = 1;
            result = (int) (prime * result + (this.aceObjectFlags == null ? 0 : this.aceObjectFlags.asUInt()));
            result = (int) (prime * result + (this.aceRight == null ? 0 : this.aceRight.asUInt()));
            result = prime * result + (this.inheritedObjectType == null ? 0 : this.inheritedObjectType.GetHashCode());
            result = prime * result + (this.objectType == null ? 0 : this.objectType.GetHashCode());
            result = prime * result + (this.requiredFlag == null ? 0 : this.requiredFlag.GetHashCode());
            result = prime * result + (this.excludedFlag == null ? 0 : this.excludedFlag.GetHashCode());
            return result;
        }

        public override bool Equals(object obj)
        {
            if (this == obj)
            {
                return true;
            }

            if (obj == null)
            {
                return false;
            }

            if (!(obj is AceAssertion other))
            {
                return false;
            }

            if (this.aceObjectFlags == null)
            {
                if (other.aceObjectFlags != null)
                {
                    return false;
                }
            }
            else if (other.aceObjectFlags == null)
            {
                return false;
            }
            else if (this.aceObjectFlags != null && other.aceObjectFlags != null)
            {
                if (!this.aceObjectFlags.getFlags().All(x => other.aceObjectFlags.getFlags().Contains(x)) || this.aceObjectFlags.getOthers() != other.aceObjectFlags.getOthers())
                {
                    return false;
                }
            }

            if (this.aceRight == null)
            {
                if (other.aceRight != null)
                {
                    return false;
                }
            }
            else if (other.aceRight == null)
            {
                return false;
            }
            else if (this.aceRight != null && other.aceRight != null)
            {
                if (!this.aceRight.getObjectRights().All(x => other.aceRight.getObjectRights().Contains(x)) || this.aceRight.getOthers() != other.aceRight.getOthers())
                {
                    return false;
                }
            }

            if (this.inheritedObjectType == null)
            {
                if (other.inheritedObjectType != null)
                {
                    return false;
                }
            }
            else if (!this.inheritedObjectType.Equals(other.inheritedObjectType))
            {
                return false;
            }

            if (this.objectType == null)
            {
                if (other.objectType != null)
                {
                    return false;
                }
            }
            else if (!this.objectType.Equals(other.objectType))
            {
                return false;
            }

            if (this.requiredFlag == null)
            {
                if (other.requiredFlag != null)
                {
                    return false;
                }
            }
            else if (other.requiredFlag == null)
            {
                return false;
            }
            else if (this.requiredFlag != other.requiredFlag)
            {
                return false;
            }

            if (this.excludedFlag == null)
            {
                if (other.excludedFlag != null)
                {
                    return false;
                }
            }
            else if (other.excludedFlag == null)
            {
                return false;
            }
            else if (this.excludedFlag != other.excludedFlag)
            {
                return false;
            }

            return true;
        }

        public override string ToString()
        {
            string right = this.aceRight == null ? "null" : this.aceRight.asUInt().ToString();
            string objFlags = this.aceObjectFlags == null ? "null" : this.aceObjectFlags.asUInt().ToString();
            string reqFlag = this.requiredFlag == null ? "null" : this.requiredFlag.ToString();
            string exFlag = this.excludedFlag == null ? "null" : this.excludedFlag.ToString();

            return "AceAssertion [aceRight=" + right + this.getRightsAbbrevStringForToString() + ", aceObjectFlags=" + objFlags
                + ", objectType="
                + this.objectType
                + ", inheritedObjectType=" + this.inheritedObjectType + ", requiredFlag=" + reqFlag + ", excludedFlag="
                + exFlag + "]";
        }

        public string getRightsAbbrevStringForToString() => "(" + this.getRightsAbbrevString() + ")";

        public string getRightsAbbrevString()
        {
            if (this.aceRight == null)
            {
                return "null";
            }

            var rightsCode = "?";
            foreach (AceRights.ObjectRight rightVal in Enum.GetValues(typeof(AceRights.ObjectRight)))
            {
                if ((this.aceRight.asUInt() & (uint) rightVal) == (uint) rightVal)
                {
                    rightsCode = rightVal.ToString();
                    break;
                }
            }

            if (rightsCode.Equals("?"))
            {
                switch ((int) this.aceRight.asUInt())
                {
                    case 0x00000001:
                        rightsCode = "CC";
                        break;
                    case 0x00000002:
                        rightsCode = "DC";
                        break;
                    case 0x00000004:
                        rightsCode = "LC";
                        break;
                    case 0x00000008:
                        rightsCode = "VW";
                        break;
                    case 0x00000010:
                        rightsCode = "RP";
                        break;
                    case 0x00000020:
                        rightsCode = "WP";
                        break;
                    case 0x00000040:
                        rightsCode = "DT";
                        break;
                    case 0x00000080:
                        rightsCode = "LO";
                        break;

                    // The below are 'first class' rights in the AceRights.ObjectRight enum, therefore
                    // they don't need to be decoded here.
                    // case 0x00000100:
                    // return "CR";
                    // break;
                    // case 0x00010000:
                    // return "DE";
                    // break;
                    // case 0x00020000:
                    // return "RC";
                    // break;
                    // case 0x00040000:
                    // return "WD";
                    // break;
                    // case 0x00080000:
                    // return "WO";
                    // break;
                    // case 0x00100000:
                    // return "SY";
                    // break;
                    // case 0x01000000:
                    // return "AS";
                    // break;
                    // case 0x02000000:
                    // return "MA";
                    // break;
                    // case 0x10000000:
                    // return "GA";
                    // break;
                    // case 0x20000000:
                    // return "GX";
                    // break;
                }
            }

            return rightsCode;
        }
    }
}