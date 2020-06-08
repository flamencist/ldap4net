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
using System.IO;
using System.Linq;
using System.Text;
using LdapForNet.Adsddl.data;
using LdapForNet.Adsddl.utils;

namespace LdapForNet.Adsddl
{
    /// <summary>
    ///     An access control entry (ACE) is used to encode the user rights afforded to a principal, either a user or group.
    ///     This
    ///     is generally done by combining an ACCESS_MASK and the SID of the principal.
    /// </summary>
    public class ACE
    {
        /// <summary>
        ///     Optional application data.
        /// </summary>
        private byte[] applicationData;

        /// <summary>
        ///     AceFlag
        /// </summary>
        private List<AceFlag> flags;

        /// <summary>
        ///     A GUID (16 bytes) that identifies the type of child object that can inherit the ACE.
        /// </summary>
        private Guid? inheritedObjectType;

        /// <summary>
        ///     AceObjectFlags
        /// </summary>
        private AceObjectFlags objectFlags;

        /// <summary>
        ///     A GUID (16 bytes) that identifies a property set, property, extended right, or type of child object.
        /// </summary>
        private Guid? objectType;

        /// <summary>
        ///     AceRights
        /// </summary>
        private AceRights rights;

        /// <summary>
        ///     The SID of a trustee.
        /// </summary>
        private SID sid;

        /// <summary>
        ///     AceType
        /// </summary>
        private AceType type;

        /// <summary>
        ///     Creates a new ACE instance.
        ///     @param type ACE type.
        ///     @return ACE.
        /// </summary>
        public static ACE newInstance(AceType type)
        {
            ACE ace = new ACE();
            ace.setType(type);
            return ace;
        }

        /// <summary>
        ///     Load the ACE from the buffer returning the last ACE segment position into the buffer.
        ///     @param buff source buffer.
        ///     @param start start loading position.
        ///     @return last loading position.
        /// </summary>
        public void parse(BinaryReader buff)
        {
            var start = buff.BaseStream.Position;
            byte[] bytes = NumberFacility.getBytes(buff.ReadInt32());
            this.type = AceTypeExtension.parseValue(bytes[0]);
            this.flags = AceFlagExtension.parseValue(bytes[1]);

            int size = NumberFacility.getInt(bytes[3], bytes[2]);
            
            this.rights = AceRights.parseValue(NumberFacility.getReverseInt(buff.ReadInt32()));

            if (this.type == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE || this.type == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
            {
                this.objectFlags = AceObjectFlags.parseValue(NumberFacility.getReverseInt(buff.ReadInt32()));

                if (this.objectFlags.getFlags().Contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT))
                {
                    this.objectType = new Guid(buff.ReadBytes(16));
                }

                if (this.objectFlags.getFlags().Contains(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT))
                {
                    this.inheritedObjectType = new Guid(buff.ReadBytes(16));
                }
            }
            
            this.sid = new SID();
            this.sid.parse(buff);

            if (size > 0)
            {
                var lastPos = start + size;
                this.applicationData = new byte[lastPos - buff.BaseStream.Position];

                for (var i = 0; i < applicationData.Length; i++)
                {
                    this.applicationData[i] = buff.ReadByte();
                }
            }
        }

        /// <summary>
        ///     Gets ACE type.
        ///     AceType
        ///     @return ACE type.
        /// </summary>
        public AceType getType() => this.type;

        /// <summary>
        ///     Gets ACE flags.
        ///     AceFlag
        ///     @return ACE flags; empty list if no flag has been specified.
        /// </summary>
        public List<AceFlag> getFlags() => this.flags == null ? new List<AceFlag>() : this.flags;

        /// <summary>
        ///     Optional application data. The size of the application data is determined by the AceSize field.
        ///     @return application data; null if not available.
        /// </summary>
        public byte[] getApplicationData()
            => this.applicationData == null || this.applicationData.Length == 0
                ? null
                : this.applicationData.Copy();

        /// <summary>
        ///     Sets application data.
        ///     @param applicationData application data.
        /// </summary>
        public void setApplicationData(byte[] applicationData)
            => this.applicationData = applicationData == null || applicationData.Length == 0
                ? null
                : applicationData.Copy();

        /// <summary>
        ///     An ACCESS_MASK that specifies the user rights allowed by this ACE.
        ///     AceRights
        ///     @return ACE rights.
        /// </summary>
        public AceRights getRights() => this.rights;

        /// <summary>
        ///     A 32-bit unsigned integer that specifies a set of bit flags that indicate whether the ObjectType and
        ///     InheritedObjectType fields contain valid data. This parameter can be one or more of the following values.
        ///     AceObjectFlags
        ///     @return Flags.
        /// </summary>
        public AceObjectFlags getObjectFlags() => this.objectFlags;

        /// <summary>
        ///     A GUID (16 bytes) that identifies a property set, property, extended right, or type of child object. The purpose
        ///     of this GUID depends on the user rights specified in the Mask field. This field is valid only if the ACE
        ///     _OBJECT_TYPE_PRESENT bit is set in the Flags field. Otherwise, the ObjectType field is ignored. For information
        ///     on access rights and for a mapping of the control access rights to the corresponding GUID value that identifies
        ///     each right, see [MS-ADTS] sections 5.1.3.2 and 5.1.3.2.1.
        ///     ACCESS_MASK bits are not mutually exclusive. Therefore, the ObjectType field can be set in an ACE with any
        ///     ACCESS_MASK. If the AccessCheck algorithm calls this ACE and does not find an appropriate GUID, then that ACE
        ///     will be ignored. For more information on access checks and object access, see [MS-ADTS] section 5.1.3.3.3.
        ///     @return ObjectType; null if not available.
        /// </summary>
        public Guid? getObjectType() => this.objectType;

        /// <summary>
        ///     A GUID (16 bytes) that identifies the type of child object that can inherit the ACE. Inheritance is also
        ///     controlled by the inheritance flags in the ACE_HEADER, as well as by any protection against inheritance placed on
        ///     the child objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set in the Flags
        ///     member. Otherwise, the InheritedObjectType field is ignored.
        ///     @return InheritedObjectType; null if not available.
        /// </summary>
        public Guid? getInheritedObjectType() => this.inheritedObjectType;

        /// <summary>
        ///     The SID of a trustee. The length of the SID MUST be a multiple of 4.
        ///     SID
        ///     @return SID of the trustee.
        /// </summary>
        public SID getSid() => this.sid;

        /// <summary>
        ///     An unsigned 16-bit integer that specifies the size, in bytes, of the ACE. The AceSize field can be greater than
        ///     the sum of the individual fields, but MUST be a multiple of 4 to ensure alignment on a DWORD boundary. In cases
        ///     where the AceSize field encompasses additional data for the callback ACEs types, that data is
        ///     implementation-specific. Otherwise, this additional data is not interpreted and MUST be ignored.
        ///     @return ACE size.
        /// </summary>
        public int getSize()
            => 8 + (this.objectFlags == null ? 0 : 4)
                + (this.objectType == null ? 0 : 16)
                + (this.inheritedObjectType == null ? 0 : 16)
                + (this.sid == null ? 0 : this.sid.getSize())
                + (this.applicationData == null ? 0 : this.applicationData.Length);

        /// <summary>
        ///     Sets ACE type.
        ///     @param type ACE type.
        ///     AceType
        /// </summary>
        public void setType(AceType type) => this.type = type;

        /// <summary>
        ///     Adds ACE flag.
        ///     @param flag ACE flag.
        ///     AceFlag
        /// </summary>
        public void addFlag(AceFlag flag) => this.flags.Add(flag);

        /// <summary>
        ///     Sets ACE rights.
        ///     @param rights ACE rights.
        ///     AceRights
        /// </summary>
        public void setRights(AceRights rights) => this.rights = rights;

        /// <summary>
        ///     Sets object flags.
        ///     @param objectFlags ACE object flags.
        ///     AceObjectFlags
        /// </summary>
        public void setObjectFlags(AceObjectFlags objectFlags) => this.objectFlags = objectFlags;

        /// <summary>
        ///     Sets object type, a GUID (16 bytes) that identifies a property set, property, extended right, or type of child
        ///     object.
        ///     @param objectType ACE object type.
        /// </summary>
        public void setObjectType(Guid? objectType) => this.objectType = objectType;

        /// <summary>
        ///     Sets inherited object type, a GUID (16 bytes) that identifies the type of child object that can inherit the ACE.
        ///     @param inheritedObjectType Inherited object type.
        /// </summary>
        public void setInheritedObjectType(Guid? inheritedObjectType) => this.inheritedObjectType = inheritedObjectType;

        /// <summary>
        ///     Sets the SID of a trustee.
        ///     @param sid SID of the trustee.
        ///     SID
        /// </summary>
        public void setSid(SID sid) => this.sid = sid;

        /// <summary>
        ///     Serializes to byte array.
        ///     @return serialized ACE.
        /// </summary>
        public byte[] toByteArray()
        {
            int size = this.getSize();

            using var ms = new MemoryStream(size);
            var buff = new BinaryWriter(ms);

            // Add type byte
            buff.Write((byte) this.type);

            // add flags byte
            byte flagSrc = this.getFlags().Aggregate<AceFlag, byte>(0x00, (current, flag) => (byte) (current | (byte) flag));

            buff.Write(flagSrc);

            // add size bytes (2 reversed)
            byte[] sizeSrc = NumberFacility.getBytes(size);
            buff.Write(sizeSrc[3]);
            buff.Write(sizeSrc[2]);

            // add right mask
            buff.Write(Hex.reverse(NumberFacility.getUIntBytes(this.rights.asUInt())));

            // add object flags (from int to byte[] + reversed)
            if (this.objectFlags != null)
            {
                buff.Write(Hex.reverse(NumberFacility.getUIntBytes(this.objectFlags.asUInt())));
            }

            // add object type
            if (this.objectType != null)
            {
                buff.Write(this.objectType.Value.ToByteArray());
            }

            // add inherited object type
            if (this.inheritedObjectType != null)
            {
                buff.Write(this.inheritedObjectType.Value.ToByteArray());
            }

            // add sid
            buff.Write(this.sid.toByteArray());

            // add application data
            if (this.applicationData != null)
            {
                buff.Write(this.applicationData);
            }

            return ms.ToArray();
        }

        public override bool Equals(object ace)
        {
            if (!(ace is ACE ext))
            {
                return false;
            }

            if (this.getSize() != ext.getSize())
            {
                return false;
            }

            if (this.getType() != ext.getType())
            {
                return false;
            }

            if (!this.getApplicationData().SequenceEqual(ext.getApplicationData()))
            {
                return false;
            }

            if (!this.getSid().Equals(ext.getSid()))
            {
                return false;
            }

            if (this.getObjectFlags() == null && ext.getObjectFlags() != null
                || this.getObjectFlags() != null && ext.getObjectFlags() == null
                || this.getObjectFlags() != null && ext.getObjectFlags() != null
                && this.getObjectFlags().asUInt() != ext.getObjectFlags().asUInt())
            {
                return false;
            }

            if (this.getObjectType() != null && ext.getObjectType() == null
                || this.getObjectType() == null && ext.getObjectType() != null
                || this.getObjectType() != null && ext.getObjectType() != null
                && this.getObjectType() != ext.getObjectType())
            {
                return false;
            }

            if (this.getInheritedObjectType() != null && ext.getInheritedObjectType() == null
                || this.getInheritedObjectType() == null && ext.getInheritedObjectType() != null
                || this.getInheritedObjectType() != null && ext.getInheritedObjectType() != null
                && this.getInheritedObjectType() != ext.getInheritedObjectType())
            {
                return false;
            }

            if (this.getRights().asUInt() != ext.getRights().asUInt())
            {
                return false;
            }

            return new HashSet<AceFlag>(this.getFlags()).Equals(new HashSet<AceFlag>(ext.getFlags()));
        }

        public override string ToString()
        {
            StringBuilder bld = new StringBuilder();
            bld.Append('(');
            bld.Append(this.type.GetString());
            bld.Append(';');

            foreach (AceFlag flag in this.flags)
            {
                bld.Append(flag.GetString());
            }

            bld.Append(';');

            foreach (AceRights.ObjectRight right in this.rights.getObjectRights())
            {
                bld.Append(right.ToString());
            }

            if (this.rights.getOthers() != 0)
            {
                bld.Append('[');
                bld.Append(this.rights.getOthers());
                bld.Append(']');
            }

            bld.Append(';');

            if (this.objectType != null)
            {
                bld.Append(this.objectType.ToString());
            }

            bld.Append(';');

            if (this.inheritedObjectType != null)
            {
                bld.Append(this.inheritedObjectType.ToString());
            }

            bld.Append(';');

            bld.Append(this.sid);

            bld.Append(')');

            return bld.ToString();
        }

        public override int GetHashCode()
        {
            var hash = 3;
            hash = 53 * hash + this.type.GetHashCode();
            hash = 53 * hash + this.flags.GetHashCode();
            hash = 53 * hash + this.rights.GetHashCode();
            hash = 53 * hash + this.objectFlags.GetHashCode();
            hash = 53 * hash + this.objectType.GetHashCode();
            hash = 53 * hash + this.inheritedObjectType.GetHashCode();
            hash = 53 * hash + this.applicationData.GetHashCode();
            hash = 53 * hash + this.sid.GetHashCode();
            return hash;
        }
    }
}