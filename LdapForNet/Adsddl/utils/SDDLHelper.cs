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

using System.Collections.Generic;
using System.Linq;
using LdapForNet.Adsddl.data;

namespace LdapForNet.Adsddl.utils
{
    /// <summary>
    ///     SDDL helper class.
    ///     Provides facilities to set and unset specific ACLs.
    /// </summary>
    public class SDDLHelper
    {
        /// <summary>
        ///     User cannot change password GUID.
        /// </summary>
        public static string UCP_OBJECT_GUID = "ab721a53-1e2f-11d0-9819-00aa0040529b";

        /// <summary>
        ///     Check if user canot change password.
        ///     @param sddl SSDL.
        ///     @return <tt>true</tt> if user cannot change password: <tt>false</tt> otherwise.
        /// </summary>
        public static bool isUserCannotChangePassword(SDDL sddl)
        {
            var res = false;

            List<ACE> aces = sddl.getDacl().getAces();
            for (var i = 0; !res && i < aces.Count; i++)
            {
                ACE ace = aces[i];

                if (ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE
                    && ace.getObjectFlags().getFlags().Contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT))
                {
                    if (GUID.getGuidAsString(ace.getObjectType()).Equals(UCP_OBJECT_GUID))
                    {
                        SID sid = ace.getSid();
                        if (sid.getSubAuthorities().Count == 1)
                        {
                            if (sid.getIdentifierAuthority().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })
                                && sid.getSubAuthorities().First().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                                || sid.getIdentifierAuthority().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 })
                                && sid.getSubAuthorities().First().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x0a }))
                            {
                                res = true;
                            }
                        }
                    }
                }
            }

            return res;
        }

        /// <summary>
        ///     Set "User Cannot Change Password ACL".
        ///     @param sddl SDDL.
        ///     @param cannot <tt>true</tt> to set the ACL; <tt>false</tt> to unset.
        ///     @return updated SDDL.
        /// </summary>
        public static SDDL userCannotChangePassword(SDDL sddl, bool cannot)
        {
            AceType type = cannot ? AceType.ACCESS_DENIED_OBJECT_ACE_TYPE : AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE;

            ACE self = null;
            ACE all = null;

            List<ACE> aces = sddl.getDacl().getAces();
            for (var i = 0; (all == null || self == null) && i < aces.Count; i++)
            {
                ACE ace = aces[i];

                if ((ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
                        || ace.getType() == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
                    && ace.getObjectFlags().getFlags().Contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT))
                {
                    if (GUID.getGuidAsString(ace.getObjectType()).Equals(UCP_OBJECT_GUID))
                    {
                        SID sid = ace.getSid();
                        if (sid.getSubAuthorities().Count == 1)
                        {
                            if (self == null
                                && sid.getIdentifierAuthority().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })
                                && sid.getSubAuthorities().First().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00 }))
                            {
                                self = ace;
                                self.setType(type);
                            }
                            else if (all == null
                                && sid.getIdentifierAuthority().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 })
                                && sid.getSubAuthorities().First().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x0a }))
                            {
                                all = ace;
                                all.setType(type);
                            }
                        }
                    }
                }
            }

            if (self == null)
            {
                // prepare aces
                self = ACE.newInstance(type);
                self.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
                self.setObjectType(GUID.getGuidAsByteArray(UCP_OBJECT_GUID));
                self.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.CR));
                SID sid = SID.newInstance(NumberFacility.getBytes(0x000000000001, 6));
                sid.addSubAuthority(NumberFacility.getBytes(0));
                self.setSid(sid);
                sddl.getDacl().getAces().Add(self);
            }

            if (all == null)
            {
                all = ACE.newInstance(type);
                all.setObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT));
                all.setObjectType(GUID.getGuidAsByteArray(UCP_OBJECT_GUID));
                all.setRights(new AceRights().addOjectRight(AceRights.ObjectRight.CR));
                SID sid = SID.newInstance(NumberFacility.getBytes(0x000000000005, 6));
                sid.addSubAuthority(NumberFacility.getBytes(0x0A));
                all.setSid(sid);
                sddl.getDacl().getAces().Add(all);
            }

            return sddl;
        }
    }
}