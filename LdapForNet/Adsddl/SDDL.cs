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

using System.IO;
using System.Linq;
using System.Text;
using LdapForNet.Adsddl.utils;

namespace LdapForNet.Adsddl
{
    /// <summary>
    ///     The SECURITY_DESCRIPTOR structure defines the security attributes of an object. These attributes specify who owns
    ///     the object; who can access the object and what they can do with it; what level of audit logging should be applied
    ///     to the object; and what kind of restrictions apply to the use of the security descriptor.
    ///     Security descriptors appear in one of two forms, absolute or self-relative.
    ///     A security descriptor is said to be in absolute format if it stores all of its security information via pointer
    ///     fields, as specified in the RPC representation in section 2.4.6.1.
    ///     A security descriptor is said to be in self-relative format if it stores all of its security information in a
    ///     contiguous block of memory and expresses all of its pointer fields as offsets from its beginning. The order of
    ///     appearance of pointer target fields is not required to be in any particular order; locating the OwnerSid, GroupSid,
    ///     Sacl, and/or Dacl should only be based on OffsetOwner, OffsetGroup, OffsetSacl, and/or OffsetDacl pointers found in
    ///     the fixed portion of the relative security descriptor.
    ///     The self-relative form of the security descriptor is required if one wants to transmit the SECURITY_DESCRIPTOR
    ///     structure as an opaque data structure for transmission in communication protocols over a wire, or for storage
    ///     on secondary media; the absolute form cannot be transmitted because it contains pointers to objects that are
    ///     generally not accessible to the recipient.
    ///     When a self-relative security descriptor is transmitted over a wire, it is sent in little-endian format and
    ///     requires no padding.
    ///     <see href="https://msdn.microsoft.com/en-us/library/cc230366.aspx">cc230366</see>
    /// </summary>
    public class SDDL
    {
        /// <summary>
        ///     An unsigned 16-bit field that specifies control access bit flags. The Self Relative (SR) bit MUST be set when the
        ///     security descriptor is in self-relative format.
        /// </summary>
        private byte[] controlFlags;

        /// <summary>
        ///     The SACL of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the SP flag
        ///     is set.
        /// </summary>
        private ACL dacl;

        /// <summary>
        ///     The SID of the group of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if
        ///     the GroupOwner field is not zero.
        /// </summary>
        private SID group;

        /// <summary>
        ///     An unsigned 32-bit integer that specifies the offset to the ACL that contains ACEs that control access.
        ///     Typically, the DACL contains ACEs that grant or deny access to principals or groups. This must be a valid offset
        ///     if the DP flag is set; if the DP flag is not set, this field MUST be set to zero. If this field is set to zero,
        ///     the Dacl field MUST not be present.
        /// </summary>
        private long offsetDACL;

        /// <summary>
        ///     An unsigned 32-bit integer that specifies the offset to the SID. This SID specifies the group of the object to
        ///     which the security descriptor is associated. This must be a valid offset if the GD flag is not set. If this field
        ///     is set to zero, the GroupSid field MUST not be present.
        /// </summary>
        private long offsetGroup;

        /// <summary>
        ///     An unsigned 32-bit integer that specifies the offset to the SID. This SID specifies the owner of the object to
        ///     which the security descriptor is associated. This must be a valid offset if the OD flag is not set. If this field
        ///     is set to zero, the OwnerSid field MUST not be present.
        /// </summary>
        private long offsetOwner;

        /// <summary>
        ///     An unsigned 32-bit integer that specifies the offset to the ACL that contains system ACEs. Typically, the system
        ///     ACL contains auditing ACEs (such as SYSTEM_AUDIT_ACE, SYSTEM_AUDIT_CALLBACK_ACE, or
        ///     SYSTEM_AUDIT_CALLBACK_OBJECT_ACE), and at most one Label ACE. This must be a valid offset if the SP flag is set;
        ///     if the SP flag is not set, this field MUST be set to zero. If this field is set to zero, the Sacl field MUST not
        ///     be present.
        /// </summary>
        private long offsetSACL;

        /// <summary>
        ///     The SID of the owner of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if
        ///     the OffsetOwner field is not zero.
        /// </summary>
        private SID owner;

        /// <summary>
        ///     An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR structure.
        ///     This field MUST be set to one.
        /// </summary>
        private byte revision;

        /// <summary>
        ///     The DACL of the object. The length of the SID MUST be a multiple of 4. This field MUST be present if the DP flag
        ///     is set.
        /// </summary>
        private ACL sacl;

        /// <summary>
        ///     Constructor.
        ///     @param src source as byte array.
        /// </summary>
        public SDDL(byte[] src)
        {
            using var ms = new MemoryStream(src);
            using var sddlBuffer = new BinaryReader(ms);
            this.parse(sddlBuffer, 0);
        }

        /// <summary>
        ///     Load the SDDL from the buffer returning the last SDDL segment position into the buffer.
        ///     @param buff source buffer.
        ///     @param start start loading position.
        ///     @return last loading position.
        /// </summary>
        private void parse(BinaryReader buff, long start)
        {
            // Revision (1 byte): An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR
            // structure. This field MUST be set to one.
            buff.BaseStream.Seek(start, SeekOrigin.Begin);
            byte[] header = NumberFacility.getBytes(buff.ReadInt32());
            this.revision = header[0];

            // Control (2 bytes): An unsigned 16-bit field that specifies control access bit flags. The Self Relative
            // (SR) bit MUST be set when the security descriptor is in self-relative format.
            this.controlFlags = new[] { header[3], header[2] };
            bool[] controlFlag = NumberFacility.getBits(this.controlFlags);

            // OffsetOwner (4 bytes): An unsigned 32-bit integer that specifies the offset to the SID. This SID
            // specifies the owner of the object to which the security descriptor is associated. This must be a valid
            // offset if the OD flag is not set. If this field is set to zero, the OwnerSid field MUST not be present.
            if (!controlFlag[15])
            {
                this.offsetOwner = NumberFacility.getReverseUInt(buff.ReadInt32());
            }
            else
            {
                this.offsetOwner = 0;
            }

            // OffsetGroup (4 bytes): An unsigned 32-bit integer that specifies the offset to the SID. This SID
            // specifies the group of the object to which the security descriptor is associated. This must be a valid
            // offset if the GD flag is not set. If this field is set to zero, the GroupSid field MUST not be present.
            if (!controlFlag[14])
            {
                this.offsetGroup = NumberFacility.getReverseUInt(buff.ReadInt32());
            }
            else
            {
                this.offsetGroup = 0;
            }

            // OffsetSacl (4 bytes): An unsigned 32-bit integer that specifies the offset to the ACL that contains
            // system ACEs. Typically, the system ACL contains auditing ACEs (such as SYSTEM_AUDIT_ACE,
            // SYSTEM_AUDIT_CALLBACK_ACE, or SYSTEM_AUDIT_CALLBACK_OBJECT_ACE), and at most one Label ACE (as specified
            // in section 2.4.4.13). This must be a valid offset if the SP flag is set; if the SP flag is not set, this
            // field MUST be set to zero. If this field is set to zero, the Sacl field MUST not be present.
            if (controlFlag[11])
            {
                this.offsetSACL = NumberFacility.getReverseUInt(buff.ReadInt32());
            }
            else
            {
                this.offsetSACL = 0;
            }

            // OffsetDacl (4 bytes): An unsigned 32-bit integer that specifies the offset to the ACL that contains ACEs
            // that control access. Typically, the DACL contains ACEs that grant or deny access to principals or groups.
            // This must be a valid offset if the DP flag is set; if the DP flag is not set, this field MUST be set to
            // zero. If this field is set to zero, the Dacl field MUST not be present.
            if (controlFlag[13])
            {
                this.offsetDACL = NumberFacility.getReverseUInt(buff.ReadInt32());
            }
            else
            {
                this.offsetDACL = 0;
            }

            // OwnerSid (variable): The SID of the owner of the object. The length of the SID MUST be a multiple of 4.
            // This field MUST be present if the OffsetOwner field is not zero.
            if (this.offsetOwner > 0)
            {
                // read for OwnerSid
                this.owner = new SID();
                this.owner.parse(buff, this.offsetOwner);
            }

            // GroupSid (variable): The SID of the group of the object. The length of the SID MUST be a multiple of 4.
            // This field MUST be present if the GroupOwner field is not zero.
            if (this.offsetGroup > 0)
            {
                // read for GroupSid
                this.group = new SID();
                this.group.parse(buff, this.offsetGroup);
            }

            // Sacl (variable): The SACL of the object. The length of the SID MUST be a multiple of 4. This field MUST
            // be present if the SP flag is set.
            if (this.offsetSACL > 0)
            {
                // read for Sacl
                this.sacl = new ACL();
                this.sacl.parse(buff, this.offsetSACL);
            }

            // Dacl (variable): The DACL of the object. The length of the SID MUST be a multiple of 4. This field MUST
            // be present if the DP flag is set.
            if (this.offsetDACL > 0)
            {
                this.dacl = new ACL(); 
                this.dacl.parse(buff, this.offsetDACL);
            }
        }

        /// <summary>
        ///     Gets size in terms of number of bytes.
        ///     @return size.
        /// </summary>
        public int getSize()
            => 20 + (this.sacl == null ? 0 : this.sacl.getSize())
                + (this.dacl == null ? 0 : this.dacl.getSize())
                + (this.owner == null ? 0 : this.owner.getSize())
                + (this.group == null ? 0 : this.group.getSize());

        /// <summary>
        ///     Get revison.
        ///     @return An unsigned 8-bit value that specifies the revision of the SECURITY_DESCRIPTOR structure..
        /// </summary>
        public byte getRevision() => this.revision;

        /// <summary>
        ///     Gets control.
        ///     @return An unsigned 16-bit field that specifies control access bit flags.
        /// </summary>
        public byte[] getControlFlags() => this.controlFlags;

        /// <summary>
        ///     Gets owner.
        ///     @return The SID of the owner of the object.
        /// </summary>
        public SID getOwner() => this.owner;

        /// <summary>
        ///     Gets group.
        ///     @return The SID of the group of the object.
        /// </summary>
        public SID getGroup() => this.group;

        /// <summary>
        ///     Gets DACL.
        ///     @return The DACL of the object.
        /// </summary>
        public ACL getDacl() => this.dacl;

        /// <summary>
        ///     Gets SACL.
        ///     @return The SACL of the object.
        /// </summary>
        public ACL getSacl() => this.sacl;

        /// <summary>
        ///     Serializes SDDL as byte array.
        ///     @return SDL as byte array.
        /// </summary>
        public byte[] toByteArray()
        {
            using var ms = new MemoryStream(this.getSize());
            var buff = new BinaryWriter(ms);

            // add revision
            buff.Write(this.revision);

            // add reserved
            buff.Write((byte) 0x00);

            // add contro flags
            buff.Write(this.controlFlags[1]);
            buff.Write(this.controlFlags[0]);

            // add offset owner
            buff.Seek(4, SeekOrigin.Begin);

            var nextAvailablePosition = 20;

            // add owner SID
            if (this.owner == null)
            {
                buff.Write(0);
            }
            else
            {
                buff.Write(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
                buff.Seek(nextAvailablePosition, SeekOrigin.Begin);
                buff.Write(this.owner.toByteArray());
                nextAvailablePosition += this.owner.getSize();
            }

            // add offset group
            buff.Seek(8, SeekOrigin.Begin);

            // add group SID
            if (this.group == null)
            {
                buff.Write(0);
            }
            else
            {
                buff.Write(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
                buff.Seek(nextAvailablePosition, SeekOrigin.Begin);
                buff.Write(this.group.toByteArray());
                nextAvailablePosition += this.group.getSize();
            }

            // add offset sacl
            buff.Seek(12, SeekOrigin.Begin);

            // add SACL
            if (this.sacl == null)
            {
                buff.Write(0);
            }
            else
            {
                buff.Write(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
                buff.Seek(nextAvailablePosition, SeekOrigin.Begin);
                buff.Write(this.sacl.toByteArray());
                nextAvailablePosition += this.sacl.getSize();
            }

            // add offset dacl
            buff.Seek(16, SeekOrigin.Begin);

            // add DACL
            if (this.dacl == null)
            {
                buff.Write(0);
            }
            else
            {
                buff.Write(Hex.reverse(NumberFacility.getBytes(nextAvailablePosition)));
                buff.Seek(nextAvailablePosition, SeekOrigin.Begin);
                buff.Write(this.dacl.toByteArray());
            }

            return ms.ToArray();
        }

        public override bool Equals(object o)
        {
            if (!(o is SDDL ext))
            {
                return false;
            }

            if (this.getSize() != ext.getSize())
            {
                return false;
            }

            if (!this.getControlFlags().SequenceEqual(ext.getControlFlags()))
            {
                return false;
            }

            if (!this.getOwner().Equals(ext.getOwner()))
            {
                return false;
            }

            if (!this.getGroup().Equals(ext.getGroup()))
            {
                return false;
            }

            if (!this.getDacl().Equals(ext.getDacl()))
            {
                return false;
            }

            if (!this.getSacl().Equals(ext.getSacl()))
            {
                return false;
            }

            return true;
        }

        public override string ToString()
        {
            StringBuilder bld = new StringBuilder();

            if (this.owner != null)
            {
                bld.Append("O:");
                bld.Append(this.owner);
            }

            if (this.group != null)
            {
                bld.Append("G:");
                bld.Append(this.group);
            }

            if (this.dacl != null)
            {
                bld.Append("D:");
                bld.Append(this.dacl);
            }

            if (this.sacl != null)
            {
                bld.Append("S:");
                bld.Append(this.sacl);
            }

            return bld.ToString();
        }

        public override int GetHashCode()
        {
            var hash = 5;
            hash = 71 * hash + this.controlFlags.GetHashCode();
            hash = 71 * hash + this.owner.GetHashCode();
            hash = 71 * hash + this.group.GetHashCode();
            hash = 71 * hash + this.dacl.GetHashCode();
            hash = 71 * hash + this.sacl.GetHashCode();
            return hash;
        }
    }
}