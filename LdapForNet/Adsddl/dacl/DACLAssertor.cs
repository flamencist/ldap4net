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
* Copyright © 2018-2019 VMware, Inc. All Rights Reserved.
*
* COPYING PERMISSION STATEMENT
* SPDX-License-Identifier: Apache-2.0
*/

using System;
using System.Collections.Generic;
using System.Linq;
using LdapForNet.Adsddl.data;
using LdapForNet.Utils;

namespace LdapForNet.Adsddl.dacl
{
    /// <summary>
    ///     A class which asserts whether the DACL (Discretionary Access Control List) of an AD object grants the principal of
    ///     an AdRoleAssertion all the rights which the assertion contains.
    ///     The caller must specify the LDAP search filter which will be used to locate the given object in the domain
    ///     and fetch its nTSecurityDescriptor attribute, which contains the DACL.Alternatively, a constructor accepting
    ///     a pre-created DACL is available.The DACL is then searched for all ACE entries which
    ///     are expected to satisfy AceAssertions specified by the AdRoleAssertion; the assertion is
    ///     passed in to the method doAssert. If there are unsatisfied assertions, and the adRoleAssertion refers
    ///     to a user, the evaluation is repeated for all groups the user belongs to.The caller may then evaluate the result of
    ///     doAssert and identify unsatisfied assertions by calling getUnsatisfiedAssertions.
    ///     Denied rights are now detected and included in the result, if they are determined to override
    ///     satisfied rights.
    ///     Only non-inherited denials can override a right which is granted.
    ///     The 'Everyone' AD group is also evaluted if constructed with searchGroups = true
    ///     <see href="https://msdn.microsoft.com/en-us/library/cc223510.aspx"> cc223510 </see>
    /// </summary>
    public class DaclAssertor
    {
        /// <summary>
        ///     SID of the 'Everyone' AD group.
        /// </summary>
        private static readonly string everyoneSID = "S-1-1-0";

        /// <summary>
        ///     LDAP search filter for the object whose DACL will be evaluated.
        /// </summary>
        private readonly string searchFilter;

        /// <summary>
        ///     Whether to search the groups of the roleAssertion principal.
        /// </summary>
        private readonly bool searchGroups;

        /// <summary>
        ///     The parsed DACL.
        /// </summary>
        private Acl dacl;

        /// <summary>
        ///     Pre-connected LdapContext.
        /// </summary>
        private readonly LdapConnection ldapContext;

        /// <summary>
        ///     List of any unsatisfied AceAssertions after doAssert runs.
        /// </summary>
        private List<AceAssertion> unsatisfiedAssertions = new List<AceAssertion>();

        /// <summary>
        ///     DACLAssertor constructor.
        ///     @param searchFilter
        ///     LDAP search filter, locating an object whose DACL will be evaluated against the AdRoleAssertion.
        ///     <b>
        ///         NOTE: LDAP
        ///         filter escaping is the caller's responsibility
        ///     </b>
        ///     @param searchGroups
        ///     whether to search groups of a user contained in the AdRoleAssertion
        ///     @param ldapContext
        ///     the pre-connected LDAP context
        /// </summary>
        public DaclAssertor(string searchFilter, bool searchGroups, LdapConnection ldapContext)
        {
            this.searchFilter = searchFilter;
            this.searchGroups = searchGroups;
            this.ldapContext = ldapContext;
        }

        /// <summary>
        ///     DACLAssertor constructor. This version takes a pre-created DACL.
        ///     @param dacl
        ///     the DACL of the object to evaluate against the AdRoleAssertion
        ///     @param searchGroups
        ///     whether to search groups of a user contained in the AdRoleAssertion
        /// </summary>
        public DaclAssertor(Acl dacl, bool searchGroups)
        {
            this.dacl = dacl;
            this.searchGroups = searchGroups;
        }

        /// <summary>
        ///     Compares the object DACL located by the searchFilter against the specified AdRoleAssertion, and
        ///     determines whether
        ///     that assertion's principal is granted all the rights which the assertion contains.
        ///     When comparing ACEs of the DACL, only those of AceType.ACCESS_ALLOWED_ACE_TYPE or
        ///     AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE will be considered for satisfying an AceAssertion of
        ///     the roleAssertion.
        ///     Once completed, any unsatisfied assertions can be obtained by calling getUnsatisfiedAssertions}.
        ///     Denied rights are now detected and included in the result, if they are determined to override
        ///     satisfied rights.
        ///     @param roleAssertion
        ///     the AdRoleAssertion
        ///     @return true if the DACL fulfills the claims of the roleAssertion, false otherwise.
        ///     @throws CommunicationException
        ///     if the context for searching the DACL is invalid or the domain cannot be reached
        ///     @throws NameNotFoundException
        ///     if the DACL search fails
        ///     @throws NamingException
        ///     if extracting the DACL fails or another JNDI issue occurs
        ///     @throws SizeLimitExceededException
        ///     if more than one AD object found during DACL search
        /// </summary>
        public bool DoAssert(AdRoleAssertion roleAssertion)
        {
            if (roleAssertion.GetPrincipal() == null)
            {
                return false;
            }

            if (this.dacl == null)
            {
                if (this.ldapContext == null)
                {
                    return false;
                }
                this.GetDacl();
            }

            this.unsatisfiedAssertions = this.FindUnsatisfiedAssertions(roleAssertion);
            return this.unsatisfiedAssertions.Count == 0;
        }

        /// <summary>
        ///     Returns list of AceAssertions in the AdRoleAssertion given to {@linkplain doAssert} which are unsatisfied.
        ///     @return list of unsatisfied AceAssertions
        /// </summary>
        public List<AceAssertion> GetUnsatisfiedAssertions() => this.unsatisfiedAssertions;

        /// <summary>
        ///     Fetches the DACL of the object which is evaluated by
        ///     {@linkplain net.tirasa.adsddl.ntsd.dacl.DACLAssertor#doAssert}
        ///     @throws CommunicationException
        ///     @throws NameNotFoundException
        ///     @throws NamingException
        /// </summary>
        private void GetDacl()
        {
            SearchRequest directoryRequest = new SearchRequest(LdapUtils.GetDnFromHostname(), 
                "", 
                Native.Native.LdapSearchScope.LDAP_SCOPE_SUBTREE) 
                { Attributes = { LdapAttributes.NtSecurityDescriptor } };
            directoryRequest.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl));
            SearchResponse response = (SearchResponse) this.ldapContext.SendRequest(directoryRequest);
            DirectoryEntry entry = response.Entries.FirstOrDefault();
            if (entry == null)
            {
                throw new LdapException("Couldn't find ldap");
            }

            byte[] descbytes = entry.GetBytes(LdapAttributes.NtSecurityDescriptor);
            Sddl sddl = new Sddl(descbytes);
            this.dacl = sddl.GetDacl();
        }

        /// <summary>
        ///     Evaluates whether the DACL fulfills the given AdRoleAssertion and returns the list of unsatisfied AceAssertions
        ///     (if any).
        ///     If the assertor was constructed with {@code searchGroups = true} and the roleAssertion specifies a user,
        ///     then
        ///     all group SIDs contained in the roleAssertion will be tested for potential matches in the DACL if any
        ///     rights are
        ///     not directly granted to the user. Also, the 'Everyone' AD group will also be scanned.
        ///     Denied rights are now detected and included in the resulting list.
        ///     @param roleAssertion
        ///     the AdRoleAssertion to test
        ///     @return List of unsatisfied AceAssertions (if any). Empty if none.
        /// </summary>
        private List<AceAssertion> FindUnsatisfiedAssertions(AdRoleAssertion roleAssertion)
        {
            var acesBySIDMap = new Dictionary<string, List<Ace>>();

            for (var i = 0; i < this.dacl.GetAceCount(); i++)
            {
                Ace ace = this.dacl.GetAce(i);
                if (ace.GetSid() != null)
                {
                    if (!acesBySIDMap.ContainsKey(ace.GetSid().ToString()))
                    {
                        acesBySIDMap.Add(ace.GetSid().ToString(), new List<Ace>());
                    }

                    acesBySIDMap[ace.GetSid().ToString()].Add(ace);
                }
            }

            // Find any roleAssertion ACEs not matched in the DACL.
            // Not using Java 8 or other libs for this to keep dependencies of ADSDDL as is.
            // ------------------------------
            var unsatisfiedAssertions = new List<AceAssertion>(roleAssertion.GetAssertions());
            var deniedAssertions = new List<AceAssertion>();
            SID principal = roleAssertion.GetPrincipal();

            if (acesBySIDMap.ContainsKey(principal.ToString()))
            {
                this.FindUnmatchedAssertions(acesBySIDMap[principal.ToString()], unsatisfiedAssertions, deniedAssertions, roleAssertion.GetAssertions());
            }

            // There may be denials on groups even if we resolved all assertions - search groups if specified
            if (this.searchGroups)
            {
                if (roleAssertion.IsGroup())
                {
                    this.DoEveryoneGroupScan(acesBySIDMap, unsatisfiedAssertions, deniedAssertions, roleAssertion.GetAssertions());
                    this.MergeDenials(unsatisfiedAssertions, deniedAssertions);
                    return unsatisfiedAssertions;
                }

                List<SID> tokenGroupSiDs = roleAssertion.GetTokenGroups();
                if (tokenGroupSiDs == null)
                {
                    this.DoEveryoneGroupScan(acesBySIDMap, unsatisfiedAssertions, deniedAssertions, roleAssertion.GetAssertions());
                    this.MergeDenials(unsatisfiedAssertions, deniedAssertions);
                    return unsatisfiedAssertions;
                }

                foreach (SID grpSID in tokenGroupSiDs.Where(grpSID => acesBySIDMap.ContainsKey(grpSID.ToString())))
                {
                    this.FindUnmatchedAssertions(acesBySIDMap[grpSID.ToString()], unsatisfiedAssertions, deniedAssertions, roleAssertion.GetAssertions());
                }

                this.DoEveryoneGroupScan(acesBySIDMap, unsatisfiedAssertions, deniedAssertions, roleAssertion.GetAssertions());
            }

            this.MergeDenials(unsatisfiedAssertions, deniedAssertions);

            return unsatisfiedAssertions;
        }

        private void DoEveryoneGroupScan(
            Dictionary<string, List<Ace>> acesBySIDMap,
            List<AceAssertion> unsatisfiedAssertions,
            List<AceAssertion> deniedAssertions,
            List<AceAssertion> roleAssertions)
        {
            List<Ace> everyoneAcEs = acesBySIDMap[everyoneSID];
            this.FindUnmatchedAssertions(everyoneAcEs, unsatisfiedAssertions, deniedAssertions, roleAssertions);
        }

        /// <summary>
        ///     Finds which AceAssertions are satisfied by the given list of ACEs, and removes those from the unsatisfied list.
        ///     Also finds ACEs which are explicitly denied and adds those to the deniedAssertions list if they match any
        ///     roleAssertions. Upon returning, only the assertions still unmatched will be in the given
        ///     {@code unsatisfiedAssertions} list, and denials will accumulate in the {@code deniedAssertions} list.
        ///     @param aces
        ///     ACE list to be evaluated
        ///     @param unsatisfiedAssertions
        ///     list of AceAssertions currently unmatched in the DACL.
        ///     @param deniedAssertions
        ///     list of AceAssertions denied in the DACL.
        ///     @param roleAssertions
        ///     the AceAssertions from the AdRoleAssertion
        /// </summary>
        private void FindUnmatchedAssertions(List<Ace> aces, List<AceAssertion> unsatisfiedAssertions,
            List<AceAssertion> deniedAssertions, List<AceAssertion> roleAssertions)
        {
            if (aces == null || aces.Count == 0)
            {
                return;
            }

            foreach (Ace ace in aces)
            {
                long rightsMask = ace.GetRights().AsUInt();

                bool isDenial = ace.GetAceType() == AceType.AccessDeniedAceType
                    || ace.GetAceType() == AceType.AccessDeniedObjectAceType;

                // can only match type ACCESS_ALLOWED or ACCESS_ALLOWED_OBJECT, if not a denial
                if (!isDenial
                    && ace.GetAceType() != AceType.AccessAllowedAceType
                    && ace.GetAceType() != AceType.AccessAllowedObjectAceType)
                {
                    continue;
                }

                foreach (AceAssertion assertion in roleAssertions)
                {
                    long assertRight = assertion.GetAceRight().AsUInt();

                    var isMatch = false;
                    if ((rightsMask & assertRight) == assertRight)
                    {
                        // found a rights match
                        if (this.DoObjectFlagsMatch(ace.GetObjectFlags(), assertion.GetObjectFlags())
                            && this.DoObjectTypesMatch(
                                ace.GetObjectType(),
                                assertion.GetObjectType(),
                                assertion.GetObjectFlags())
                            && this.DoInheritedObjectTypesMatch(
                                ace.GetInheritedObjectType(),
                                assertion.GetInheritedObjectType(),
                                assertion.GetObjectFlags())
                            && this.DoRequiredFlagsMatch(ace.GetFlags(), assertion.GetRequiredFlag(), isDenial)
                            && !this.IsAceExcluded(ace.GetFlags(), assertion.GetExcludedFlag(), isDenial))
                        {
                            isMatch = true;
                        }
                    }

                    if (isMatch)
                    {
                        if (!isDenial)
                        {
                            unsatisfiedAssertions.Remove(assertion);
                        }
                        else
                        {
                            this.AddDeniedAssertion(deniedAssertions, assertion);
                        }
                    }
                }
            }
        }

        /// <summary>
        ///     This routine adds the deniedAssertion to the given list of them, if not already present.
        ///     Not using {@code Set.add} which relies on the AceAssertion equals method, because of the possible variance
        ///     in AceAssertion properties besides the AceRights, which do not matter for purposes of tracking the denials.
        ///     @param deniedAssertions
        ///     the list of already denied assertions
        ///     @param assertion
        ///     the assertion to add if not present in deniedAssertions
        /// </summary>
        private void AddDeniedAssertion(List<AceAssertion> deniedAssertions, AceAssertion assertion)
        {
            long deniedRight = assertion.GetAceRight().AsUInt();
            var found = false;
            foreach (AceAssertion a in deniedAssertions)
            {
                if ((a.GetAceRight().AsUInt() & deniedRight) == deniedRight)
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                deniedAssertions.Add(assertion);
            }
        }

        /// <summary>
        ///     This routine merges deniedAssertions into the unsatisfiedAssertions, avoiding duplicates.
        ///     @param unsatisfiedAssertions
        ///     the list of unsatisifed assertions
        ///     @param deniedAssertions
        ///     list of denied assertions
        /// </summary>
        private void MergeDenials(List<AceAssertion> unsatisfiedAssertions, List<AceAssertion> deniedAssertions)
        {
            var toAddList = new List<AceAssertion>();
            foreach (AceAssertion denial in deniedAssertions)
            {
                var found = false;
                foreach (AceAssertion unsat in unsatisfiedAssertions)
                {
                    if (unsat.GetAceRight().AsUInt() == denial.GetAceRight().AsUInt())
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    toAddList.Add(denial);
                }
            }

            unsatisfiedAssertions.AddRange(toAddList);
        }

        /// <summary>
        ///     Compares the AceObjectFlags attribute of an ACE against that of an AceAssertion. If the {@code assertionObjFlags}
        ///     are null, a true result is returned.
        ///     If the {@code assertionObjFlags} are not null, then either the {@code aceObjFlags} must be a match, or they
        ///     must
        ///     not be set. The not set case is deemed a match because MS AD documentation states that if an object type
        ///     (referred to by the flags) is also empty, then the ACE controls the ability to perform operations of the
        ///     given access right on all object classes. In this case, the decision about the ACE matching (regarding the
        ///     object)
        ///     is left up to the {@linkplain doObjectTypesMatch} and {@linkplain doInheritedObjectTypesMatch} methods.
        ///     An ACE will appear without object flags when it is for "Full Control" permissions.
        ///     @param aceObjFlags
        ///     object flags from the ACE
        ///     @param assertionObjFlags
        ///     object flags from the AceAssertion
        ///     @return true if match, false if not
        /// </summary>
        private bool DoObjectFlagsMatch(AceObjectFlags aceObjFlags, AceObjectFlags assertionObjFlags)
        {
            var res = true;
            if (assertionObjFlags != null)
            {
                if (aceObjFlags != null
                    && (aceObjFlags.AsUInt() & assertionObjFlags.AsUInt()) == assertionObjFlags.AsUInt())
                {
                    res = true;
                }
                else if (aceObjFlags == null || aceObjFlags.AsUInt() == 0)
                {
                    // MS docs state that if the object type is _not_ present - which is hinted at by presence of object flags -
                    // then the ACE controls that right on all object classes/attributes of such objects.
                    // So defer ultimate decision to object/inherited object type matching.
                    res = true;
                }
                else
                {
                    res = false;
                }
            }

            return res;
        }

        /// <summary>
        ///     Checks whether the object type identified by the ACE matches the object type of the AceAssertion given. If the
        ///     {@code assertionObjFlags} are null, or they do not specify ACE_OBJECT_TYPE_PRESENT, a true result is returned.
        ///     @param aceObjectType
        ///     byte array containing the ACE objectType GUID
        ///     @param assertionObjectType
        ///     string containing the AceAssertion objectType
        ///     @param assertionObjFlags
        ///     AceObjectFlags from the AceAssertion
        ///     @return true if match, false if not
        /// </summary>
        private bool DoObjectTypesMatch(Guid? aceObjectType, Guid? assertionObjectType, AceObjectFlags assertionObjFlags)
        {
            if (assertionObjFlags == null)
            {
                return true;
            }

            if ((assertionObjFlags.AsUInt()
                & (uint) AceObjectFlags.Flag.AceObjectTypePresent) == (uint) AceObjectFlags.Flag.AceObjectTypePresent)
            {
                if (aceObjectType != null && aceObjectType != assertionObjectType)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        ///     Checks whether the inherited object type identified by the ACE matches the inherited object type of the
        ///     AceAssertion given. If the assertionObjFlags are null, or they do not specify
        ///     ACE_INHERITED_OBJECT_TYPE_PRESENT, a true result is returned.
        ///     @param aceInhObjectType
        ///     byte array containing the ACE inheritedObjectType GUID
        ///     @param assertionInhObjectType
        ///     string containing the AceAssertion inheritedObjectType
        ///     @param assertionObjFlags
        ///     AceObjectFlags from the AceAssertion
        ///     @return true if match, false if not
        /// </summary>
        private bool DoInheritedObjectTypesMatch(Guid? aceInhObjectType, Guid? assertionInhObjectType, AceObjectFlags assertionObjFlags)
        {
            if (assertionObjFlags == null)
            {
                return true;
            }

            if ((assertionObjFlags.AsUInt() & (uint) AceObjectFlags.Flag.AceInheritedObjectTypePresent) == (uint) AceObjectFlags.Flag.AceInheritedObjectTypePresent)
            {
                if (aceInhObjectType != null && aceInhObjectType != assertionInhObjectType)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>
        ///     Checks whether the AceFlags attribute of the ACE contains the given AceFlag of the AceAssertion. If the
        ///     requiredFlag is null, yet the aceFlags are not (or empty), or vice versa, or they DO NOT contain
        ///     the required flag, a false result is returned.
        ///     @param aceFlags
        ///     list of AceFlags from the ACE
        ///     @param requiredFlag
        ///     AceFlag required by the AceAssertion (e.g., AceFlag.CONTAINER_INHERIT_ACE)
        ///     @param isDenial
        ///     whether the AceType is a denial, in which case the aceFlags must not contain AceFlag.INHERITED_ACE
        ///     and the requiredFlag is ignored.
        ///     @return true if match, false if not
        /// </summary>
        private bool DoRequiredFlagsMatch(List<AceFlag> aceFlags, AceFlag requiredFlag, bool isDenial)
        {
            var res = true;
            if (isDenial)
            {
                // If the AceType is denial, the flags must NOT contain the inherited flag. Such denials are ineffective
                // when countered by an allowed right, so we only consider non-inherited denials as a match.
                if (aceFlags == null || !aceFlags.Contains(AceFlag.InheritedAce))
                {
                    res = true;
                }
                else
                {
                    res = false;
                }
            }
            else if (requiredFlag != AceFlag.None)
            {
                // aceFlags could be null if the ACE applies to 'this object only' and has no other flags set
                if (aceFlags == null || aceFlags.Count == 0 || !aceFlags.Contains(requiredFlag))
                {
                    res = false;
                }
            }
            else if (aceFlags != null && aceFlags.Count != 0)
            {
                res = false;
            }

            return res;
        }

        /// <summary>
        ///     Checks whether the AceFlags attribute of the ACE contains the given AceFlag of the AceAssertion. If the
        ///     excludedFlag is null, or the {@code aceFlags} are null (or empty), or are non-null and do DO NOT contain
        ///     the excluded flag, a false result is returned. Otherwise, a true result is returned.
        ///     @param aceFlags
        ///     list of AceFlags from the ACE
        ///     @param excludedFlag
        ///     AceFlag disallowed by the AceAssertion (e.g., AceFlag.INHERIT_ONLY_ACE)
        ///     @param isDenial
        ///     whether the AceType is a denial, in which case the excludedFlag evaluation is skipped
        ///     @return true if AceFlags is excluded, false if not
        /// </summary>
        private bool IsAceExcluded(List<AceFlag> aceFlags, AceFlag excludedFlag, bool isDenial)
        {
            var res = false;
            if (excludedFlag != AceFlag.None && !isDenial)
            {
                // aceFlags could be null if the ACE applies to 'this object only' and has no other flags set
                if (aceFlags != null && aceFlags.Count != 0 && aceFlags.Contains(excludedFlag))
                {
                    res = true;
                }
            }

            return res;
        }
    }
}