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
using System.Collections.Generic;
using System.Linq;
using LdapForNet.Adsddl.data;

namespace LdapForNet.Adsddl.dacl
{
    /// <summary>
    ///     Represents an AdRoleAssertion which specifies the criteria required to join or remove computers
    ///     to/from an AD domain in a given container (& its children) without any restrictions. This includes the ability
    ///     to reset AD computer passwords, which is needed by some systems that manage domain joined computers.
    /// </summary>
    public class DomainJoinRoleAssertion : AdRoleAssertion
    {
        /// <summary>
        ///     Schema GUID of "CN=Computer,CN=Schema,CN=Configuration" objects
        /// </summary>
        protected static Guid computerSchemaIDGuid = new Guid("bf967a86-0de6-11d0-a285-00aa003049e2");

        /// <summary>
        ///     Schema GUID of "CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration" extended right
        ///     (aka "reset password")
        /// </summary>
        protected static Guid resetPasswordCrGuid = new Guid("00299570-246d-11d0-a768-00aa006e0529");

        protected static AceAssertion createComputer = new AceAssertion(
            AceRights.ParseValue(0x00000001),
            new AceObjectFlags(AceObjectFlags.Flag.AceObjectTypePresent),
            computerSchemaIDGuid,
            null,
            AceFlag.ContainerInheritAce,
            AceFlag.InheritOnlyAce);

        protected static AceAssertion deleteComputer = new AceAssertion(
            AceRights.ParseValue(0x00000002),
            new AceObjectFlags(AceObjectFlags.Flag.AceObjectTypePresent),
            computerSchemaIDGuid,
            null,
            AceFlag.ContainerInheritAce,
            AceFlag.InheritOnlyAce);

        protected static AceAssertion listContents = new AceAssertion(
            AceRights.ParseValue(0x00000004),
            null,
            null,
            null,
            AceFlag.ContainerInheritAce,
            AceFlag.InheritOnlyAce);

        protected static AceAssertion readProperties = new AceAssertion(
            AceRights.ParseValue(0x00000010),
            null,
            null,
            null,
            AceFlag.ContainerInheritAce,
            AceFlag.InheritOnlyAce);

        protected static AceAssertion writeProperties = new AceAssertion(
            AceRights.ParseValue(0x00000020),
            null,
            null,
            null,
            AceFlag.ContainerInheritAce,
            AceFlag.None);

        protected static AceAssertion readPermissions = new AceAssertion(
            AceRights.ParseValue(0x00020000),
            null,
            null,
            null,
            AceFlag.ContainerInheritAce,
            AceFlag.InheritOnlyAce);

        protected static AceAssertion resetPassword = new AceAssertion(
            AceRights.ParseValue((int) AceRights.ObjectRight.Cr),
            new AceObjectFlags(AceObjectFlags.Flag.AceObjectTypePresent, AceObjectFlags.Flag.AceInheritedObjectTypePresent),
            resetPasswordCrGuid,
            computerSchemaIDGuid,
            AceFlag.ContainerInheritAce,
            AceFlag.None);

        protected static readonly AceAssertion[] DomainJoinAssertions =
        {
            createComputer,
            deleteComputer,
            listContents,
            readProperties,
            writeProperties,
            readPermissions,
            resetPassword
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
            : base(DomainJoinAssertions.ToList(), principal, isGroup, tokenGroups) { }
    }
}