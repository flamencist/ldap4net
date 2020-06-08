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
using LdapForNet.Adsddl.data;

namespace LdapForNet.Adsddl.data
{
    /**
 * An unsigned 8-bit integer that specifies the ACE types.
 *
 * <see href="https://msdn.microsoft.com/en-us/library/cc230296.aspx">cc230296</see>
 */
    public enum AceType
    {
        /// <summary>
        /// Unexpected value.
        /// </summary>
        UNEXPECTED = 0xFF,

        /// <summary>
        /// 0x00 - Access-allowed ACE that uses the ACCESS_ALLOWED_ACE structure.
        /// </summary>
        ACCESS_ALLOWED_ACE_TYPE = 0x00,

        /// <summary>
        /// 0x01 - Access-denied ACE that uses the ACCESS_DENIED_ACE structure.
        /// </summary>
        ACCESS_DENIED_ACE_TYPE = 0x01,

        /// <summary>
        /// 0x02 - System-audit ACE that uses the SYSTEM_AUDIT_ACE structure.
        /// </summary>
        SYSTEM_AUDIT_ACE_TYPE = 0x02,

        /// <summary>
        /// 0x03 - Reserved for future use.
        /// </summary>
        SYSTEM_ALARM_ACE_TYPE = 0x03,

        /// <summary>
        /// 0x04 - Reserved for future use.
        /// </summary>
        ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04,

        /// <summary>
        /// 0x05 - Object-specific access-allowed ACE that uses the ACCESS_ALLOWED_OBJECT_ACE structure.
        /// </summary>
        ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05,

        /// <summary>
        /// 0x06 - Object-specific access-denied ACE that uses the ACCESS_DENIED_OBJECT_ACE structure.
        /// </summary>
        ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06,

        /// <summary>
        /// 0x07 - Object-specific system-audit ACE that uses the SYSTEM_AUDIT_OBJECT_ACE structure.
        /// </summary>
        SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07,

        /// <summary>
        /// 0x09 - Reserved for future use.
        /// </summary>
        SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08,

        /// <summary>
        /// 0x09 - Access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_ACE structure.
        /// </summary>
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09,

        /// <summary>
        /// 0x0A - Access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_ACE structure.
        /// </summary>
        ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A,

        /// <summary>
        /// 0x0B - Object-specific access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_OBJECT_ACE structure.
        /// </summary>
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B,

        /// <summary>
        /// 0x0C - Object-specific access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_OBJECT_ACE structure.
        /// </summary>
        ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C,

        /// <summary>
        /// 0x0D - System-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_ACE structure.
        /// </summary>
        SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D,

        /// <summary>
        /// 0x0E - Reserved for future use.
        /// </summary>
        SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E,

        /// <summary>
        /// 0x0F - Object-specific system-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_OBJECT_ACE structure.
        /// </summary>
        SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F,

        /// <summary>
        /// 0x10 - Reserved for future use.
        /// </summary>
        SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10,

        /// <summary>
        /// 0x11 - Mandatory label ACE that uses the SYSTEM_MANDATORY_LABEL_ACE structure.
        /// </summary>
        SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11,

        /// <summary>
        /// 0x12 - Resource attribute ACE that uses the SYSTEM_RESOURCE_ATTRIBUTE_ACE.
        /// </summary>
        SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12,

        /// <summary>
        /// 0x13 - A central policy ID ACE that uses the SYSTEM_SCOPED_POLICY_ID_ACE.
        /// </summary>
        SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13
    }
}

public static class AceTypeExtension
{
    public static string GetString(this AceType type)
    {
        switch (type)
        {
            case AceType.ACCESS_ALLOWED_ACE_TYPE:
                return "A";
            case AceType.ACCESS_DENIED_ACE_TYPE:
                return "D";
            case AceType.SYSTEM_AUDIT_ACE_TYPE:
                return "AU";
            case AceType.SYSTEM_ALARM_ACE_TYPE:
                return "AL";
            case AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                return "OA";
            case AceType.ACCESS_DENIED_OBJECT_ACE_TYPE:
                return "OD";
            case AceType.SYSTEM_AUDIT_OBJECT_ACE_TYPE:
                return "OU";
            case AceType.SYSTEM_ALARM_OBJECT_ACE_TYPE:
                return "OL";
            case AceType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
                return "XA";
            case AceType.ACCESS_DENIED_CALLBACK_ACE_TYPE:
                return "XD";
            case AceType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
                return "ZA";
            case AceType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
                return "ZD";
            case AceType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE:
                return "XU";
            case AceType.SYSTEM_ALARM_CALLBACK_ACE_TYPE:
                return "XL";
            case AceType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE:
                return "ZU";
            case AceType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE:
                return "ZL";
            case AceType.SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                return "ML";
            case AceType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE:
                return "RA";
            case AceType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE:
                return "SP";
            default:
                return type.ToString();
        }
    }

    /// <summary>
    /// Parses byte value.
    /// 
    /// @param value byte value.
    /// @return ACE type.
    /// </summary>
    public static AceType parseValue(byte value)
    {
        foreach (AceType type in Enum.GetValues(typeof(AceType)))
        {
            if ((byte) type == value)
            {
                return type;
            }
        }

        return AceType.UNEXPECTED;
    }
}