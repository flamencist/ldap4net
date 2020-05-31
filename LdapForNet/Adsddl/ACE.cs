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
        ///     AceType
        /// </summary>
        private AceType type;

        /// <summary>
        ///     AceFlag
        /// </summary>
        private List<AceFlag> flags;

        /// <summary>
        ///     AceRights
        /// </summary>
        private AceRights rights;

        /// <summary>
        ///     AceObjectFlags
        /// </summary>
        private AceObjectFlags objectFlags;

        /// <summary>
        ///     A GUID (16 bytes) that identifies a property set, property, extended right, or type of child object.
        /// </summary>
        private byte[] objectType;

        /// <summary>
        ///     A GUID (16 bytes) that identifies the type of child object that can inherit the ACE.
        /// </summary>
        private byte[] inheritedObjectType;

        /// <summary>
        ///     Optional application data.
        /// </summary>
        private byte[] applicationData;

        /// <summary>
        ///     The SID of a trustee.
        /// </summary>
        private SID sid;

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
        public int parse(IntBuffer buff, int start)
        {
            int pos = start;

            byte[] bytes = NumberFacility.getBytes(buff.get(pos));
            this.type = AceType.parseValue(bytes[0]);
            this.flags = AceFlag.parseValue(bytes[1]);

            int size = NumberFacility.getInt(bytes[3], bytes[2]);

            pos++;
            this.rights = AceRights.parseValue(NumberFacility.getReverseInt(buff.get(pos)));

            if (this.type == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE || this.type == AceType.ACCESS_DENIED_OBJECT_ACE_TYPE)
            {
                pos++;
                this.objectFlags = AceObjectFlags.parseValue(NumberFacility.getReverseInt(buff.get(pos)));

                if (this.objectFlags.getFlags().contains(AceObjectFlags.Flag.ACE_OBJECT_TYPE_PRESENT))
                {
                    this.objectType = new byte[16];
                    for (var j = 0; j < 4; j++)
                    {
                        pos++;
                        System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, this.objectType, j * 4, 4);
                    }
                }

                if (this.objectFlags.getFlags().contains(AceObjectFlags.Flag.ACE_INHERITED_OBJECT_TYPE_PRESENT))
                {
                    this.inheritedObjectType = new byte[16];
                    for (var j = 0; j < 4; j++)
                    {
                        pos++;
                        System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, this.inheritedObjectType, j * 4, 4);
                    }
                }
            }

            pos++;
            this.sid = new SID();
            pos = this.sid.parse(buff, pos);

            int lastPos = start + size / 4 - 1;
            this.applicationData = new byte[4 * (lastPos - pos)];

            var index = 0;
            while (pos < lastPos)
            {
                pos++;
                System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, this.applicationData, index, 4);
                index += 4;
            }

            return pos;
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
        public byte[] getObjectType()
            => this.objectType == null || this.objectType.Length == 0
                ? null
                : this.objectType.Copy();

        /// <summary>
        ///     A GUID (16 bytes) that identifies the type of child object that can inherit the ACE. Inheritance is also
        ///     controlled by the inheritance flags in the ACE_HEADER, as well as by any protection against inheritance placed on
        ///     the child objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set in the Flags
        ///     member. Otherwise, the InheritedObjectType field is ignored.
        ///     @return InheritedObjectType; null if not available.
        /// </summary>
        public byte[] getInheritedObjectType()
            => this.inheritedObjectType == null || this.inheritedObjectType.Length == 0
                ? null
                : this.inheritedObjectType.Copy();

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
        public void setObjectType(byte[] objectType)
            => this.objectType = objectType == null || objectType.Length == 0
                ? null
                : objectType.Copy();

        /// <summary>
        ///     Sets inherited object type, a GUID (16 bytes) that identifies the type of child object that can inherit the ACE.
        ///     @param inheritedObjectType Inherited object type.
        /// </summary>
        public void setInheritedObjectType(byte[] inheritedObjectType)
            => this.inheritedObjectType = inheritedObjectType == null || inheritedObjectType.Length == 0
                ? null
                : inheritedObjectType.Copy();

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

            ByteBuffer buff = ByteBuffer.allocate(size);

            // Add type byte
            buff.put((byte) this.type);

            // add flags byte
            byte flagSRC = 0x00;
            foreach (AceFlag flag in this.getFlags())
            {
                flagSRC |= (byte) flag;
            }

            buff.put(flagSRC);

            // add size bytes (2 reversed)
            byte[] sizeSRC = NumberFacility.getBytes(size);
            buff.put(sizeSRC[3]);
            buff.put(sizeSRC[2]);

            // add right mask
            buff.put(Hex.reverse(NumberFacility.getUIntBytes(this.rights.asUInt())));

            // add object flags (from int to byte[] + reversed)
            if (this.objectFlags != null)
            {
                buff.put(Hex.reverse(NumberFacility.getUIntBytes(this.objectFlags.asUInt())));
            }

            // add object type
            if (this.objectType != null)
            {
                buff.put(this.objectType);
            }

            // add inherited object type
            if (this.inheritedObjectType != null)
            {
                buff.put(this.inheritedObjectType);
            }

            // add sid
            buff.put(this.sid.toByteArray());

            // add application data
            if (this.applicationData != null)
            {
                buff.put(this.applicationData);
            }

            return buff.array();
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
                && !this.getObjectType().SequenceEqual(ext.getObjectType()))
            {
                return false;
            }

            if (this.getInheritedObjectType() != null && ext.getInheritedObjectType() == null
                || this.getInheritedObjectType() == null && ext.getInheritedObjectType() != null
                || this.getInheritedObjectType() != null && ext.getInheritedObjectType() != null
                && !this.getInheritedObjectType().SequenceEqual(ext.getInheritedObjectType()))
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
            bld.Append(this.type.ToString());
            bld.Append(';');

            foreach (AceFlag flag in this.flags)
            {
                bld.Append(flag);
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
                bld.Append(GUID.getGuidAsString(this.objectType));
            }

            bld.Append(';');

            if (this.inheritedObjectType != null)
            {
                bld.Append(GUID.getGuidAsString(this.inheritedObjectType));
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