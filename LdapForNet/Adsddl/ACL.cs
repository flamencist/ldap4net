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
using System.IO;
using System.Linq;
using System.Text;
using LdapForNet.Adsddl.data;
using LdapForNet.Adsddl.utils;

namespace LdapForNet.Adsddl
{
    /// <summary>
    ///     The access control list (ACL) packet is used to specify a list of individual access control entries (ACEs). An ACL
    ///     packet and an array of ACEs comprise a complete access control list.
    ///     The individual ACEs in an ACL are numbered from 0 to n, where n+1 is the number of ACEs in the ACL. When editing an
    ///     ACL, an application refers to an ACE within the ACL by the ACE index.
    ///     In the absence of implementation-specific functions to access the individual ACEs, access to each ACE MUST be
    ///     computed by using the AclSize and AceCount fields to parse the wire packets following the ACL to identify each
    ///     ACE_HEADER, which in turn contains the information needed to obtain the specific ACEs.
    ///     There are two types of ACL:
    ///     - A discretionary access control list (DACL) is controlled by the owner of an object or anyone granted WRITE_DAC
    ///     access to the object. It specifies the access particular users and groups can have to an object. For example, the
    ///     owner of
    ///     a file can use a DACL to control which users and groups can and cannot have access to the file.
    ///     - A system access control list (SACL) is similar to the DACL, except that the SACL is used to audit rather than
    ///     control access to an object. When an audited action occurs, the operating system records the event in the security
    ///     log.
    ///     Each ACE in a SACL has a header that indicates whether auditing is triggered by success, failure, or both; a SID
    ///     that
    ///     specifies a particular user or security group to monitor; and an access mask that lists the operations to audit.
    ///     <see href="https://msdn.microsoft.com/en-us/library/cc230297.aspx">cc230297</see>
    /// </summary>
    public class ACL
    {
        private readonly List<ACE> aces = new List<ACE>();

        /// <summary>
        ///     An unsigned 8-bit value that specifies the revision of the ACL. The only two legitimate forms of ACLs supported
        ///     for on-the-wire management or manipulation are type 2 and type 4. No other form is valid for manipulation on the
        ///     wire. Therefore this field MUST be set to one of the following values.
        ///     ACL_REVISION (0x02) - When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, and 0x11 can be present in the ACL.
        ///     An AceType of 0x11 is used for SACLs but not for DACLs. For more information about ACE types.
        ///     ACL_REVISION_DS (0x04) - When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed. ACLs of
        ///     revision 0x04 are applicable only to directory service objects. An AceType of 0x11 is used for SACLs but not for
        ///     DACLs.
        /// </summary>
        private AclRevision revision;

        /// <summary>
        ///     Load the ACL from the buffer returning the last ACL segment position into the buffer.
        ///     @param buff source buffer.
        ///     @param start start loading position.
        ///     @return last loading position.
        /// </summary>
        public void parse(BinaryReader buff, long start)
        {
            buff.BaseStream.Seek(start, SeekOrigin.Begin);

            // read for Dacl
            byte[] bytes = NumberFacility.getBytes(buff.ReadInt32());
            this.revision = AclRevisionExtension.parseValue(bytes[0]);
            
            bytes = NumberFacility.getBytes(buff.ReadInt32());
            int aceCount = NumberFacility.getInt(bytes[1], bytes[0]);

            for (var i = 0; i < aceCount; i++)
            {
                ACE ace = new ACE();
                this.aces.Add(ace);

                ace.parse(buff);
            }
        }

        /// <summary>
        ///     Gets ACL revision.
        ///     @return revision.
        /// </summary>
        public AclRevision getRevision() => this.revision;

        /// <summary>
        ///     Gets ACL size in bytes.
        ///     @return ACL size in bytes.
        /// </summary>
        public int getSize() => 8 + this.aces.Sum(ace => ace.getSize()); // add aces

        /// <summary>
        ///     Gets ACE number: an unsigned 16-bit integer that specifies the count of the number of ACE records in the ACL.
        ///     @return ACEs' number.
        /// </summary>
        public int getAceCount() => this.aces.Count;

        /// <summary>
        ///     Gets ACL ACEs.
        ///     @return list of ACEs.
        ///     ACE
        /// </summary>
        public List<ACE> getAces() => this.aces;

        /// <summary>
        ///     Gets ACL ACE at the given position.
        ///     @param i position.
        ///     @return ACL ACE.
        ///     ACE
        /// </summary>
        public ACE getAce(int i) => this.aces[i];

        /// <summary>
        ///     Serializes to byte array.
        ///     @return serialized ACL.
        /// </summary>
        public byte[] toByteArray()
        {
            int size = this.getSize();

            using var ms = new MemoryStream(size);
            var buff = new BinaryWriter(ms);

            // add revision
            buff.Write((byte) this.revision);

            // add reserved
            buff.Write((byte) 0x00);

            // add size (2 bytes reversed)
            byte[] sizeSRC = NumberFacility.getBytes(size);
            buff.Write(sizeSRC[3]);
            buff.Write(sizeSRC[2]);

            // add ace count (2 bytes reversed)
            byte[] aceCountSRC = NumberFacility.getBytes(this.getAceCount());
            buff.Write(aceCountSRC[3]);
            buff.Write(aceCountSRC[2]);

            // add reserved (2 bytes)
            buff.Write((byte) 0x00);
            buff.Write((byte) 0x00);

            // add aces
            foreach (ACE ace in this.aces)
            {
                buff.Write(ace.toByteArray());
            }

            return ms.ToArray();
        }

        public override bool Equals(object acl)
        {
            if (!(acl is ACL ext))
            {
                return false;
            }

            if (this.getSize() != ext.getSize())
            {
                return false;
            }

            if (this.getAceCount() != ext.getAceCount())
            {
                return false;
            }

            for (var i = 0; i < this.aces.Count; i++)
            {
                if (!this.getAce(i).Equals(ext.getAce(i)))
                {
                    return false;
                }
            }

            return true;
        }

        public override string ToString()
        {
            StringBuilder bld = new StringBuilder();
            bld.Append('P');

            foreach (ACE ace in this.aces)
            {
                bld.Append(ace);
            }

            return bld.ToString();
        }

        public override int GetHashCode()
        {
            var hash = 7;
            hash = 43 * hash + this.aces.GetHashCode();
            return hash;
        }
    }
}