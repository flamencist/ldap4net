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
using LdapForNet.Adsddl.data;

namespace LdapForNet.Adsddl.utils
{
    /// <summary>
    ///     SDDL helper class.
    ///     Provides facilities to set and unset specific ACLs.
    /// </summary>
    public class SddlHelper
    {
        /// <summary>
        ///     User cannot change password GUID.
        /// </summary>
        public static Guid ucpObjectGuid = new Guid("ab721a53-1e2f-11d0-9819-00aa0040529b");

        /// <summary>
        ///     Check if user canot change password.
        ///     @param sddl SSDL.
        ///     @return <tt>true</tt> if user cannot change password: <tt>false</tt> otherwise.
        /// </summary>
        public static bool IsUserCannotChangePassword(Sddl sddl)
        {
            var res = false;

            List<Ace> aces = sddl.GetDacl().GetAces();
            for (var i = 0; !res && i < aces.Count; i++)
            {
                Ace ace = aces[i];

                if (ace.GetAceType() == AceType.AccessDeniedObjectAceType
                    && ace.GetObjectFlags().GetFlags().Contains(AceObjectFlags.Flag.AceObjectTypePresent))
                {
                    if (ace.GetObjectType() == ucpObjectGuid)
                    {
                        SID sid = ace.GetSid();
                        if (sid.GetSubAuthorities().Count == 1)
                        {
                            if (sid.GetIdentifierAuthority().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })
                                && sid.GetSubAuthorities().First().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00 })
                                || sid.GetIdentifierAuthority().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 })
                                && sid.GetSubAuthorities().First().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x0a }))
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
        public static Sddl UserCannotChangePassword(Sddl sddl, bool cannot)
        {
            AceType type = cannot ? AceType.AccessDeniedObjectAceType : AceType.AccessAllowedObjectAceType;

            Ace self = null;
            Ace all = null;

            List<Ace> aces = sddl.GetDacl().GetAces();
            for (var i = 0; (all == null || self == null) && i < aces.Count; i++)
            {
                Ace ace = aces[i];

                if ((ace.GetAceType() == AceType.AccessAllowedObjectAceType
                        || ace.GetAceType() == AceType.AccessDeniedObjectAceType)
                    && ace.GetObjectFlags().GetFlags().Contains(AceObjectFlags.Flag.AceObjectTypePresent))
                {
                    if (ace.GetObjectType() == ucpObjectGuid)
                    {
                        SID sid = ace.GetSid();
                        if (sid.GetSubAuthorities().Count == 1)
                        {
                            if (self == null
                                && sid.GetIdentifierAuthority().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 })
                                && sid.GetSubAuthorities().First().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00 }))
                            {
                                self = ace;
                                self.SetType(type);
                            }
                            else if (all == null
                                && sid.GetIdentifierAuthority().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 })
                                && sid.GetSubAuthorities().First().SequenceEqual(new byte[] { 0x00, 0x00, 0x00, 0x0a }))
                            {
                                all = ace;
                                all.SetType(type);
                            }
                        }
                    }
                }
            }

            if (self == null)
            {
                // prepare aces
                self = Ace.NewInstance(type);
                self.SetObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.AceObjectTypePresent));
                self.SetObjectType(ucpObjectGuid);
                self.SetRights(new AceRights().AddOjectRight(AceRights.ObjectRight.Cr));
                SID sid = SID.NewInstance(NumberFacility.GetBytes(0x000000000001, 6));
                sid.AddSubAuthority(NumberFacility.GetBytes(0));
                self.SetSid(sid);
                sddl.GetDacl().GetAces().Add(self);
            }

            if (all == null)
            {
                all = Ace.NewInstance(type);
                all.SetObjectFlags(new AceObjectFlags(AceObjectFlags.Flag.AceObjectTypePresent));
                all.SetObjectType(ucpObjectGuid);
                all.SetRights(new AceRights().AddOjectRight(AceRights.ObjectRight.Cr));
                SID sid = SID.NewInstance(NumberFacility.GetBytes(0x000000000005, 6));
                sid.AddSubAuthority(NumberFacility.GetBytes(0x0A));
                all.SetSid(sid);
                sddl.GetDacl().GetAces().Add(all);
            }

            return sddl;
        }
    }
}