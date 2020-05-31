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

namespace LdapForNet.Adsddl.dacl
{
    /// <summary>
    ///     An AD role assertion represents a claim that a given principal meets all the criteria in the given AceAssertion
    ///     list.
    ///     These criteria are considered the requirements of a given 'role', e.g., the ability to join computers to a domain
    ///     an unlimited number of times can be considered to be a role.
    ///     An instance of this class can be passed to a DACLAssertor to actually perform the assertion against
    ///     the DACL (Discretionary Access Control List) of an AD object.
    /// </summary>
    public abstract class AdRoleAssertion
    {
        /// <summary>
        ///     List of AceAssertions.
        /// </summary>
        private readonly List<AceAssertion> assertions;

        /// <summary>
        ///     Whether the principal represents a group or not.
        /// </summary>
        private readonly bool isGroup;

        /// <summary>
        ///     SID of the principal (i.e., user or group) which is to be asserted.
        /// </summary>
        private readonly SID principal;

        /// <summary>
        ///     The tokenGroup SIDs of the principal, if a user. May be null.
        /// </summary>
        private readonly List<SID> tokenGroups;

        public AdRoleAssertion() { }

        public AdRoleAssertion(List<AceAssertion> assertions, SID principal, bool isGroup, List<SID> tokenGroups)
        {
            this.assertions = assertions;
            this.principal = principal;
            this.isGroup = isGroup;
            this.tokenGroups = tokenGroups;
        }

        /// <summary>
        ///     Gets the list of assertions
        /// </summary>
        /// <returns>assertions</returns>
        public List<AceAssertion> GetAssertions() => this.assertions;

        /// <summary>
        ///     Gets the SID of the principal
        /// </summary>
        /// <returns>principal SID</returns>
        public SID GetPrincipal() => this.principal;

        /// <summary>
        ///     Whether the principal is a group
        /// </summary>
        /// <returns>true if principal is a group, false if a user</returns>
        public bool IsGroup() => this.isGroup;

        /// <summary>
        ///     Gets the token group SIDs of the principal, may be null
        /// </summary>
        /// <returns>SIDs of the principal's token groups, if principal is a user</returns>
        public List<SID> GetTokenGroups() => this.tokenGroups;
    }
}