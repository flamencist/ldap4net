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
using LdapForNet.Adsddl.data;
using LdapForNet.Adsddl.utils;

namespace LdapForNet.Adsddl.dacl
{
    /**
    * A class which asserts whether the DACL (Discretionary Access Control List) of an AD object grants the principal of an
    * {@code AdRoleAssertion} all the rights which the assertion contains.<br>
    * <br>
    * The caller must specify the LDAP search filter which will be used to locate the given object in the domain and fetch
    * its {@code nTSecurityDescriptor} attribute, which contains the DACL.Alternatively, a constructor accepting a
    * pre-created DACL is available.The DACL is then searched for all {@code ACE} entries which
    * are expected to satisfy {@code AceAssertions} specified by the {@code AdRoleAssertion}; the assertion is passed in to
    * the method {@linkplain doAssert}. If there are unsatisfied assertions, and the adRoleAssertion refers to a user, the
    * evaluation is repeated for all groups the user belongs to.The caller may then evaluate the result of
    * {@linkplain net.tirasa.adsddl.ntsd.dacl.DACLAssertor#doAssert} and identify unsatisfied assertions by calling
    * {@linkplain net.tirasa.adsddl.ntsd.dacl.DACLAssertor#getUnsatisfiedAssertions}.<br>
    * < br >
    * Denied rights are now detected and included in the result,  if they are determined to override satisfied rights.
    * Only non-inherited denials can override a right which is granted.
    * The 'Everyone' AD group is also evaluted if constructed with { @code searchGroups = true }
    *
    * <see href = "https://msdn.microsoft.com/en-us/library/cc223510.aspx" > cc223510 </see>
    */
    public class DACLAssertor
    {
        /// <summary>
        /// SID of the 'Everyone' AD group.
        /// </summary>
        private static string EVERYONE_SID = "S-1-1-0";

        /// <summary>
        /// LDAP search filter for the object whose DACL will be evaluated.
        /// </summary>
        private string searchFilter;

        /// <summary>
        /// Pre-connected LdapContext.
        /// </summary>
        private LdapContext ldapContext;

        /// <summary>
        /// Whether to search the groups of the roleAssertion principal.
        /// </summary>
        private bool searchGroups;

        /// <summary>
        /// The parsed DACL.
        /// </summary>
        private ACL dacl;

        /// <summary>
        /// List of any unsatisfied AceAssertions after doAssert runs.
        /// </summary>
        private List<AceAssertion> unsatisfiedAssertions = new List<AceAssertion>();

        /// <summary>
        /// DACLAssertor constructor.
        /// 
        /// @param searchFilter
        /// LDAP search filter, locating an object whose DACL will be evaluated against the AdRoleAssertion. <b>NOTE: LDAP
        /// filter escaping is the caller's responsibility</b>
        /// @param searchGroups
        /// whether to search groups of a user contained in the AdRoleAssertion
        /// @param ldapContext
        /// the pre-connected LDAP context
        /// </summary>
        public DACLAssertor(String searchFilter, bool searchGroups, LdapContext ldapContext)
        {
            this.searchFilter = searchFilter;
            this.searchGroups = searchGroups;
            this.ldapContext = ldapContext;
        }

        /// <summary>
        /// DACLAssertor constructor. This version takes a pre-created DACL.
        /// 
        /// @param dacl
        /// the DACL of the object to evaluate against the AdRoleAssertion
        /// @param searchGroups
        /// whether to search groups of a user contained in the AdRoleAssertion
        /// </summary>
        public DACLAssertor(ACL dacl, bool searchGroups)
        {
            this.dacl = dacl;
            this.searchGroups = searchGroups;
        }

        /// <summary>
        /// Compares the object DACL located by the searchFilter against the specified {@code AdRoleAssertion}, and
        /// determines whether
        /// that assertion's principal is granted all the rights which the assertion contains.<br>
        /// <br>
        /// When comparing ACEs of the DACL, only those of {@code AceType.ACCESS_ALLOWED_ACE_TYPE} or
        /// {@code AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE} will be considered for satisfying an {@code AceAssertion} of the
        /// roleAssertion.<br>
        /// <br>
        /// Once completed, any unsatisfied assertions can be obtained by calling {@linkplain getUnsatisfiedAssertions}.
        /// Denied rights are now detected and included in the result, if they are determined to override satisfied rights.
        /// 
        /// @param roleAssertion
        /// the AdRoleAssertion
        /// @return true if the DACL fulfills the claims of the roleAssertion, false otherwise.
        /// @throws CommunicationException
        /// if the context for searching the DACL is invalid or the domain cannot be reached
        /// @throws NameNotFoundException
        /// if the DACL search fails
        /// @throws NamingException
        /// if extracting the DACL fails or another JNDI issue occurs
        /// @throws SizeLimitExceededException
        /// if more than one AD object found during DACL search
        /// </summary>
        public bool doAssert(AdRoleAssertion roleAssertion)
        {
            if (roleAssertion.GetPrincipal() == null)
            {
                return false;
            }

            if (dacl == null)
            {
                getDACL();
            }

            this.unsatisfiedAssertions = findUnsatisfiedAssertions(roleAssertion);
            return this.unsatisfiedAssertions.Count == 0 ;
        }

        /// <summary>
        /// Returns list of AceAssertions in the AdRoleAssertion given to {@linkplain doAssert} which are unsatisfied.
        /// 
        /// @return list of unsatisfied AceAssertions
        /// </summary>
        public List<AceAssertion> getUnsatisfiedAssertions() => unsatisfiedAssertions;

        /// <summary>
        /// Fetches the DACL of the object which is evaluated by
        /// {@linkplain net.tirasa.adsddl.ntsd.dacl.DACLAssertor#doAssert}
        /// 
        /// @throws CommunicationException
        /// @throws NameNotFoundException
        /// @throws NamingException
        /// </summary>
        private void getDACL()
        {
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[] { "name", "nTSecurityDescriptor" });

            if (ldapContext == null)
            {
                throw new CommunicationException("NULL ldapContext");
            }

            ldapContext.setRequestControls(new Control[] { new SDFlagsControl(0x00000004) });
            
            NamingEnumeration<SearchResult> results = null;
            try
            {
                results = ldapContext.search("", searchFilter, controls);
                if (!results.hasMoreElements())
                {
                    throw new NameNotFoundException("No results found for: " + searchFilter);
                }

                SearchResult res = results.next();
                if (results.hasMoreElements())
                {
                    // result from search filter is not unique
                    throw new SizeLimitExceededException("The search filter '{}' matched more than one AD object");
                }

                byte[] descbytes = (byte[]) res.getAttributes().get("nTSecurityDescriptor").get();
                SDDL sddl = new SDDL(descbytes);
                dacl = sddl.getDacl();
            }
            finally
            {
                try
                {
                    if (results != null)
                    {
                        results.close();
                    }
                }
                catch (NamingException e)
                {
                }
            }
        }

        /// <summary>
        /// Evaluates whether the DACL fulfills the given AdRoleAssertion and returns the list of unsatisfied AceAssertions
        /// (if any).<br>
        /// <br>
        /// If the assertor was constructed with {@code searchGroups = true} and the roleAssertion specifies a user, then
        /// all group SIDs contained in the roleAssertion will be tested for potential matches in the DACL if any rights are
        /// not directly granted to the user. Also, the 'Everyone' AD group will also be scanned.<br>
        /// <br>
        /// Denied rights are now detected and included in the resulting list.
        /// 
        /// @param roleAssertion
        /// the AdRoleAssertion to test
        /// @return List of unsatisfied AceAssertions (if any). Empty if none.
        /// </summary>
        private List<AceAssertion> findUnsatisfiedAssertions(AdRoleAssertion roleAssertion)
        {
            Dictionary<String, List<ACE>> acesBySIDMap = new Dictionary<String, List<ACE>>();

            for (int i = 0; i < dacl.getAceCount(); i++)
            {
                ACE ace = dacl.getAce(i);
                if (ace.getSid() != null)
                {
                    if (!acesBySIDMap.ContainsKey(ace.getSid().ToString()))
                    {
                        acesBySIDMap.Add(ace.getSid().ToString(), new List<ACE>());
                    }

                    acesBySIDMap[ace.getSid().ToString()].Add(ace);
                }
            }

            // Find any roleAssertion ACEs not matched in the DACL.
            // Not using Java 8 or other libs for this to keep dependencies of ADSDDL as is.
            // ------------------------------
            List<AceAssertion> unsatisfiedAssertions = new List<AceAssertion>(roleAssertion.GetAssertions());
            List<AceAssertion> deniedAssertions = new List<AceAssertion>();
            SID principal = roleAssertion.GetPrincipal();
            List<ACE> principalAces = acesBySIDMap[principal.ToString()];

            if (principalAces != null)
            {
                this.findUnmatchedAssertions(principalAces, unsatisfiedAssertions, deniedAssertions, roleAssertion.GetAssertions());
            }

            // There may be denials on groups even if we resolved all assertions - search groups if specified
            if (searchGroups)
            {
                if (roleAssertion.IsGroup())
                {
                    doEveryoneGroupScan(acesBySIDMap, unsatisfiedAssertions, deniedAssertions, roleAssertion.GetAssertions());
                    mergeDenials(unsatisfiedAssertions, deniedAssertions);
                    return unsatisfiedAssertions;
                }

                List<SID> tokenGroupSIDs = roleAssertion.GetTokenGroups();
                if (tokenGroupSIDs == null)
                {
                    doEveryoneGroupScan(acesBySIDMap, unsatisfiedAssertions, deniedAssertions, roleAssertion.GetAssertions());
                    mergeDenials(unsatisfiedAssertions, deniedAssertions);
                    return unsatisfiedAssertions;
                }
                
                foreach (SID grpSID in tokenGroupSIDs) 
                {
                    principalAces = acesBySIDMap[grpSID.ToString()];
                    if (principalAces == null)
                    {
                        continue;
                    }
                    
                    findUnmatchedAssertions(principalAces, unsatisfiedAssertions, deniedAssertions, roleAssertion.GetAssertions());
                }

                doEveryoneGroupScan(acesBySIDMap, unsatisfiedAssertions, deniedAssertions, roleAssertion.GetAssertions());
            }

            mergeDenials(unsatisfiedAssertions, deniedAssertions);

            return unsatisfiedAssertions;
        }

        private void doEveryoneGroupScan(
            Dictionary<String, List<ACE>> acesBySIDMap, 
            List<AceAssertion> unsatisfiedAssertions,
            List<AceAssertion> deniedAssertions, 
            List<AceAssertion> roleAssertions)
        {
            List<ACE> everyoneACEs = acesBySIDMap[EVERYONE_SID];
            findUnmatchedAssertions(everyoneACEs, unsatisfiedAssertions, deniedAssertions, roleAssertions);
        }

        /// <summary>
        /// Finds which AceAssertions are satisfied by the given list of ACEs, and removes those from the unsatisfied list.
        /// Also finds ACEs which are explicitly denied and adds those to the deniedAssertions list if they match any
        /// roleAssertions. Upon returning, only the assertions still unmatched will be in the given 
        /// {@code unsatisfiedAssertions} list, and denials will accumulate in the {@code deniedAssertions} list.
        /// 
        /// @param aces
        /// ACE list to be evaluated
        /// @param unsatisfiedAssertions
        /// list of AceAssertions currently unmatched in the DACL.
        /// @param deniedAssertions
        /// list of AceAssertions denied in the DACL.
        /// @param roleAssertions
        /// the AceAssertions from the AdRoleAssertion
        /// </summary>
        private void findUnmatchedAssertions(List<ACE> aces, List<AceAssertion> unsatisfiedAssertions,
            List<AceAssertion> deniedAssertions, List<AceAssertion> roleAssertions)
        {
            if (aces == null || aces.Count == 0)
            {
                return;
            }

            foreach (ACE ace in aces) 
            {
                long rightsMask = ace.getRights().asUInt();

                bool isDenial = ace.getType() == AceType.ACCESS_DENIED_ACE_TYPE
                    || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE;

                // can only match type ACCESS_ALLOWED or ACCESS_ALLOWED_OBJECT, if not a denial
                if (!isDenial 
                    && ace.getType() != AceType.ACCESS_ALLOWED_ACE_TYPE
                    && ace.getType() != AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE)
                {
                    continue;
                }

                foreach (AceAssertion assertion in roleAssertions) {
                    long assertRight = assertion.getAceRight().asUInt();
                    
                    bool isMatch = false;
                    if ((rightsMask & assertRight) == assertRight)
                    {
                        // found a rights match
                        if (doObjectFlagsMatch(ace.getObjectFlags(), assertion.getObjectFlags())
                            && doObjectTypesMatch(
                                ace.getObjectType(),
                                assertion.getObjectType(),
                                assertion.getObjectFlags())
                            && doInheritedObjectTypesMatch(
                                ace.getInheritedObjectType(),
                                assertion.getInheritedObjectType(),
                                assertion.getObjectFlags())
                            && doRequiredFlagsMatch(ace.getFlags(), assertion.getRequiredFlag(), isDenial)
                            && !isAceExcluded(ace.getFlags(), assertion.getExcludedFlag(), isDenial))
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
                            addDeniedAssertion(deniedAssertions, assertion);
                        }
                    }
                }
            }
        }

        /// <summary>
        /// This routine adds the deniedAssertion to the given list of them, if not already present.
        /// Not using {@code Set.add} which relies on the AceAssertion equals method, because of the possible variance
        /// in AceAssertion properties besides the AceRights, which do not matter for purposes of tracking the denials.
        /// 
        /// @param deniedAssertions
        /// the list of already denied assertions
        /// @param assertion
        /// the assertion to add if not present in deniedAssertions
        /// </summary>
        private void addDeniedAssertion(List<AceAssertion> deniedAssertions, AceAssertion assertion)
        {
            long deniedRight = assertion.getAceRight().asUInt();
            bool found = false;
            foreach (AceAssertion a in deniedAssertions) 
            {
                if ((a.getAceRight().asUInt() & deniedRight) == deniedRight)
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
        /// This routine merges deniedAssertions into the unsatisfiedAssertions, avoiding duplicates.
        /// 
        /// @param unsatisfiedAssertions
        /// the list of unsatisifed assertions
        /// @param deniedAssertions
        /// list of denied assertions
        /// </summary>
        private void mergeDenials(List<AceAssertion> unsatisfiedAssertions, List<AceAssertion> deniedAssertions)
        {
            List<AceAssertion> toAddList = new List<AceAssertion>();
            foreach (AceAssertion denial in deniedAssertions) {
                bool found = false;
                foreach (AceAssertion unsat in unsatisfiedAssertions) {
                    if (unsat.getAceRight().asUInt() == denial.getAceRight().asUInt())
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
        /// Compares the AceObjectFlags attribute of an ACE against that of an AceAssertion. If the {@code assertionObjFlags}
        /// are null, a true result is returned.<br>
        /// <br>
        /// If the {@code assertionObjFlags} are not null, then either the {@code aceObjFlags} must be a match, or they must
        /// not be set. The not set case is deemed a match because MS AD documentation states that if an object type
        /// (referred to by the flags) is also empty, then the ACE controls the ability to perform operations of the
        /// given access right on all object classes. In this case, the decision about the ACE matching (regarding the object)
        /// is left up to the {@linkplain doObjectTypesMatch} and {@linkplain doInheritedObjectTypesMatch} methods.<br>
        /// <br>
        /// An ACE will appear without object flags when it is for "Full Control" permissions.
        /// 
        /// @param aceObjFlags
        /// object flags from the ACE
        /// @param assertionObjFlags
        /// object flags from the AceAssertion
        /// @return true if match, false if not
        /// </summary>
        private bool doObjectFlagsMatch(AceObjectFlags aceObjFlags, AceObjectFlags assertionObjFlags)
        {
            bool res = true;
            if (assertionObjFlags != null)
            {
                if (aceObjFlags != null
                    && (aceObjFlags.asUInt() & assertionObjFlags.asUInt()) == assertionObjFlags.asUInt())
                {
                    res = true;
                }
                else if (aceObjFlags == null || aceObjFlags.asUInt() == 0)
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
        /// Checks whether the object type identified by the ACE matches the object type of the AceAssertion given. If the
        /// {@code assertionObjFlags} are null, or they do not specify ACE_OBJECT_TYPE_PRESENT, a true result is returned.
        /// 
        /// @param aceObjectType
        /// byte array containing the ACE objectType GUID
        /// @param assertionObjectType
        /// string containing the AceAssertion objectType
        /// @param assertionObjFlags
        /// AceObjectFlags from the AceAssertion
        /// @return true if match, false if not
        /// </summary>
        private bool doObjectTypesMatch(byte[] aceObjectType, string assertionObjectType,
            AceObjectFlags assertionObjFlags)
        {
            bool res = true;
            if (assertionObjFlags == null)
            {
                return res;
            }

            if ((assertionObjFlags.asUInt()
                & (uint)AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT) == (uint)AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT)
            {
                if (aceObjectType != null && !GUID.getGuidAsString(aceObjectType).Equals(assertionObjectType))
                {
                    res = false;
                }
            }
            
            return res;
        }

        /// <summary>
        /// Checks whether the inherited object type identified by the ACE matches the inherited object type of the
        /// AceAssertion given. If the {@code assertionObjFlags} are null, or they do not specify
        /// ACE_INHERITED_OBJECT_TYPE_PRESENT, a true result is returned.
        /// 
        /// @param aceInhObjectType
        /// byte array containing the ACE inheritedObjectType GUID
        /// @param assertionInhObjectType
        /// string containing the AceAssertion inheritedObjectType
        /// @param assertionObjFlags
        /// AceObjectFlags from the AceAssertion
        /// @return true if match, false if not
        /// </summary>
        private bool doInheritedObjectTypesMatch(byte[] aceInhObjectType, string assertionInhObjectType,
            AceObjectFlags assertionObjFlags)
        {
            bool res = true;
            if (assertionObjFlags == null)
            {
                return res;
            }

            if ((assertionObjFlags.asUInt() & (uint)AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT) == (uint)AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT)
            {
                if (aceInhObjectType != null && !GUID.getGuidAsString(aceInhObjectType).Equals(assertionInhObjectType))
                {
                    res = false;
                }
            }
            
            return res;
        }

        /// <summary>
        /// Checks whether the AceFlags attribute of the ACE contains the given AceFlag of the AceAssertion. If the
        /// {@code requiredFlag} is null, yet the {@code aceFlags} are not (or empty), or vice versa, or they DO NOT contain
        /// the required flag, a false result is returned.
        /// 
        /// @param aceFlags
        /// list of AceFlags from the ACE
        /// @param requiredFlag
        /// AceFlag required by the AceAssertion (e.g., {@code AceFlag.CONTAINER_INHERIT_ACE})
        /// @param isDenial
        /// whether the AceType is a denial, in which case the aceFlags must not contain {@code AceFlag.INHERITED_ACE}
        /// and the requiredFlag is ignored.  
        /// @return true if match, false if not
        /// </summary>
        private bool doRequiredFlagsMatch(List<AceFlag> aceFlags, AceFlag requiredFlag, bool isDenial)
        {
            bool res = true;
            if (isDenial)
            {
                // If the AceType is denial, the flags must NOT contain the inherited flag. Such denials are ineffective
                // when countered by an allowed right, so we only consider non-inherited denials as a match.
                if (aceFlags == null || !aceFlags.Contains(AceFlag.INHERITED_ACE))
                {
                    res = true;
                }
                else
                {
                    res = false;
                }
            }
            else if (requiredFlag != null)
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
        /// Checks whether the AceFlags attribute of the ACE contains the given AceFlag of the AceAssertion. If the
        /// {@code excludedFlag} is null, or the {@code aceFlags} are null (or empty), or are non-null and do DO NOT contain
        /// the excluded flag, a false result is returned. Otherwise, a true result is returned.
        /// 
        /// @param aceFlags
        /// list of AceFlags from the ACE
        /// @param excludedFlag
        /// AceFlag disallowed by the AceAssertion (e.g., {@code AceFlag.INHERIT_ONLY_ACE})
        /// @param isDenial
        /// whether the AceType is a denial, in which case the excludedFlag evaluation is skipped
        /// @return true if AceFlags is excluded, false if not
        /// </summary>
        private bool isAceExcluded(List<AceFlag> aceFlags, AceFlag excludedFlag, bool isDenial)
        {
            bool res = false;
            if (excludedFlag != null && !isDenial)
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