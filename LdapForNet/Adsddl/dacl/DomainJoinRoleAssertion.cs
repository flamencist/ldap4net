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

using System.Collections.Generic;
using System.Linq;
using LdapForNet.Adsddl.data;

namespace LdapForNet.Adsddl.dacl
{
    /// <summary>
    ///     Represents an {@linkplain AdRoleAssertion} which specifies the criteria required to join or remove computers
    ///     to/from an AD domain in a given container (& its children) without any restrictions. This includes the ability
    ///     to reset AD computer passwords, which is needed by some systems that manage domain joined computers.
    /// </summary>
    public class DomainJoinRoleAssertion : AdRoleAssertion
    {
        /// <summary>
        ///     Schema GUID of "CN=Computer,CN=Schema,CN=Configuration" objects
        /// </summary>
        protected static string COMPUTER_SCHEMA_ID_GUID = "bf967a86-0de6-11d0-a285-00aa003049e2";

        /// <summary>
        ///     Schema GUID of "CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration" extended right
        ///     (aka "reset password")
        /// </summary>
        protected static string RESET_PASSWORD_CR_GUID = "00299570-246d-11d0-a768-00aa006e0529";

        protected static AceAssertion CREATE_COMPUTER = new AceAssertion(
            AceRights.parseValue(0x00000001),
            new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT),
            COMPUTER_SCHEMA_ID_GUID,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);

        protected static AceAssertion DELETE_COMPUTER = new AceAssertion(
            AceRights.parseValue(0x00000002),
            new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT),
            COMPUTER_SCHEMA_ID_GUID,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);

        protected static AceAssertion LIST_CONTENTS = new AceAssertion(
            AceRights.parseValue(0x00000004),
            null,
            null,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);

        protected static AceAssertion READ_PROPERTIES = new AceAssertion(
            AceRights.parseValue(0x00000010),
            null,
            null,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);

        protected static AceAssertion WRITE_PROPERTIES = new AceAssertion(
            AceRights.parseValue(0x00000020),
            null,
            null,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            null);

        protected static AceAssertion READ_PERMISSIONS = new AceAssertion(
            AceRights.parseValue(0x00020000),
            null,
            null,
            null,
            AceFlag.CONTAINER_INHERIT_ACE,
            AceFlag.INHERIT_ONLY_ACE);

        protected static AceAssertion RESET_PASSWORD = new AceAssertion(
            AceRights.parseValue((int) AceRights.ObjectRight.CR),
            new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT, AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT),
            RESET_PASSWORD_CR_GUID,
            COMPUTER_SCHEMA_ID_GUID,
            AceFlag.CONTAINER_INHERIT_ACE,
            null);

        protected static readonly AceAssertion[] DOMAIN_JOIN_ASSERTIONS =
        {
            CREATE_COMPUTER,
            DELETE_COMPUTER,
            LIST_CONTENTS,
            READ_PROPERTIES,
            WRITE_PROPERTIES,
            READ_PERMISSIONS,
            RESET_PASSWORD
        };

        /// <summary>
        ///     DomainJoinRoleAssertion constructor
        ///     @param principal
        ///     SID of the user or group
        ///     @param isGroup
        ///     whether the principal is a group
        ///     @param tokenGroups
        ///     list of token group SIDs which should be searched if the principal itself does not meet all the
        ///     criteria (when the principal is a user). May be null.
        /// </summary>
        public DomainJoinRoleAssertion(SID principal, bool isGroup, List<SID> tokenGroups)
            : base(DOMAIN_JOIN_ASSERTIONS.ToList(), principal, isGroup, tokenGroups) { }
    }
}