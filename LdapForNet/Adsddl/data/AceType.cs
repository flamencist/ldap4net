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
        Unexpected = 0xFF,

        /// <summary>
        /// 0x00 - Access-allowed ACE that uses the ACCESS_ALLOWED_ACE structure.
        /// </summary>
        AccessAllowedAceType = 0x00,

        /// <summary>
        /// 0x01 - Access-denied ACE that uses the ACCESS_DENIED_ACE structure.
        /// </summary>
        AccessDeniedAceType = 0x01,

        /// <summary>
        /// 0x02 - System-audit ACE that uses the SYSTEM_AUDIT_ACE structure.
        /// </summary>
        SystemAuditAceType = 0x02,

        /// <summary>
        /// 0x03 - Reserved for future use.
        /// </summary>
        SystemAlarmAceType = 0x03,

        /// <summary>
        /// 0x04 - Reserved for future use.
        /// </summary>
        AccessAllowedCompoundAceType = 0x04,

        /// <summary>
        /// 0x05 - Object-specific access-allowed ACE that uses the ACCESS_ALLOWED_OBJECT_ACE structure.
        /// </summary>
        AccessAllowedObjectAceType = 0x05,

        /// <summary>
        /// 0x06 - Object-specific access-denied ACE that uses the ACCESS_DENIED_OBJECT_ACE structure.
        /// </summary>
        AccessDeniedObjectAceType = 0x06,

        /// <summary>
        /// 0x07 - Object-specific system-audit ACE that uses the SYSTEM_AUDIT_OBJECT_ACE structure.
        /// </summary>
        SystemAuditObjectAceType = 0x07,

        /// <summary>
        /// 0x09 - Reserved for future use.
        /// </summary>
        SystemAlarmObjectAceType = 0x08,

        /// <summary>
        /// 0x09 - Access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_ACE structure.
        /// </summary>
        AccessAllowedCallbackAceType = 0x09,

        /// <summary>
        /// 0x0A - Access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_ACE structure.
        /// </summary>
        AccessDeniedCallbackAceType = 0x0A,

        /// <summary>
        /// 0x0B - Object-specific access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_OBJECT_ACE structure.
        /// </summary>
        AccessAllowedCallbackObjectAceType = 0x0B,

        /// <summary>
        /// 0x0C - Object-specific access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_OBJECT_ACE structure.
        /// </summary>
        AccessDeniedCallbackObjectAceType = 0x0C,

        /// <summary>
        /// 0x0D - System-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_ACE structure.
        /// </summary>
        SystemAuditCallbackAceType = 0x0D,

        /// <summary>
        /// 0x0E - Reserved for future use.
        /// </summary>
        SystemAlarmCallbackAceType = 0x0E,

        /// <summary>
        /// 0x0F - Object-specific system-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_OBJECT_ACE structure.
        /// </summary>
        SystemAuditCallbackObjectAceType = 0x0F,

        /// <summary>
        /// 0x10 - Reserved for future use.
        /// </summary>
        SystemAlarmCallbackObjectAceType = 0x10,

        /// <summary>
        /// 0x11 - Mandatory label ACE that uses the SYSTEM_MANDATORY_LABEL_ACE structure.
        /// </summary>
        SystemMandatoryLabelAceType = 0x11,

        /// <summary>
        /// 0x12 - Resource attribute ACE that uses the SYSTEM_RESOURCE_ATTRIBUTE_ACE.
        /// </summary>
        SystemResourceAttributeAceType = 0x12,

        /// <summary>
        /// 0x13 - A central policy ID ACE that uses the SYSTEM_SCOPED_POLICY_ID_ACE.
        /// </summary>
        SystemScopedPolicyIDAceType = 0x13
    }

    public static class AceTypeExtension
    {
        public static string GetString(this AceType type)
        {
            switch (type)
            {
                case AceType.AccessAllowedAceType:
                    return "A";
                case AceType.AccessDeniedAceType:
                    return "D";
                case AceType.SystemAuditAceType:
                    return "AU";
                case AceType.SystemAlarmAceType:
                    return "AL";
                case AceType.AccessAllowedObjectAceType:
                    return "OA";
                case AceType.AccessDeniedObjectAceType:
                    return "OD";
                case AceType.SystemAuditObjectAceType:
                    return "OU";
                case AceType.SystemAlarmObjectAceType:
                    return "OL";
                case AceType.AccessAllowedCallbackAceType:
                    return "XA";
                case AceType.AccessDeniedCallbackAceType:
                    return "XD";
                case AceType.AccessAllowedCallbackObjectAceType:
                    return "ZA";
                case AceType.AccessDeniedCallbackObjectAceType:
                    return "ZD";
                case AceType.SystemAuditCallbackAceType:
                    return "XU";
                case AceType.SystemAlarmCallbackAceType:
                    return "XL";
                case AceType.SystemAuditCallbackObjectAceType:
                    return "ZU";
                case AceType.SystemAlarmCallbackObjectAceType:
                    return "ZL";
                case AceType.SystemMandatoryLabelAceType:
                    return "ML";
                case AceType.SystemResourceAttributeAceType:
                    return "RA";
                case AceType.SystemScopedPolicyIDAceType:
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
        public static AceType ParseValue(byte value)
        {
            foreach (AceType type in Enum.GetValues(typeof(AceType)))
            {
                if ((byte) type == value)
                {
                    return type;
                }
            }

            return AceType.Unexpected;
        }
    }
}