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
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using LdapForNet.Adsddl.utils;

namespace LdapForNet.Adsddl
{
    /// <summary>
    ///     A security identifier (SID) uniquely identifies a security principal. Each security principal has a unique SID that
    ///     is issued by a security agent. The agent can be a Windows local system or domain. The agent generates the SID when
    ///     the security principal is created. The SID can be represented as a character string or as a structure. When
    ///     represented as strings, for example in documentation or logs, SIDs are expressed as follows:
    ///     S-1-IdentifierAuthority-SubAuthority1-SubAuthority2-...-SubAuthorityn
    ///     The top-level issuer is the authority. Each issuer specifies, in an implementation-specific manner, how many
    ///     integers
    ///     identify the next issuer.
    ///     A newly created account store is assigned a 96-bit identifier (a cryptographic strength (pseudo) random number).
    ///     A newly created security principal in an account store is assigned a 32-bit identifier that is unique within the
    ///     store.
    ///     The last item in the series of SubAuthority values is known as the relative identifier (RID). Differences in the
    ///     RID
    ///     are what distinguish the different SIDs generated within a domain.
    ///     Consumers of SIDs SHOULD NOT rely on anything more than that the SID has the appropriate structure.
    ///     <see href="https://msdn.microsoft.com/en-us/library/cc230371.aspx">cc230371</see>
    ///     <see href="https://msdn.microsoft.com/en-us/library/gg465313.aspx">gg465313</see>
    /// </summary>
    public class SID
    {
        /// <summary>
        ///     A variable length list of unsigned 32-bit integers that uniquely identifies a principal relative to the
        ///     IdentifierAuthority.
        /// </summary>
        private readonly List<byte[]> subAuthorities;

        /// <summary>
        ///     A SID_IDENTIFIER_AUTHORITY (6 bytes) structure that indicates the authority under which the SID was created.
        ///     It describes the entity that created the SID. The Identifier Authority value {0,0,0,0,0,5} denotes SIDs created
        ///     by the NT SID authority.
        /// </summary>
        private byte[] identifierAuthority;

        /// <summary>
        ///     An 8-bit unsigned integer that specifies the revision level of the SID. This value MUST be set to 0x01.
        /// </summary>
        private byte revision;

        public SID() => this.subAuthorities = new List<byte[]>();

        /// <summary>
        ///     Instances a new SID with the given identifier authority.
        ///     @param identifier identifier authority (6 bytes only).
        ///     @return the SID instance.
        /// </summary>
        public static SID newInstance(byte[] identifier)
        {
            SID sid = new SID();
            sid.setRevision(0x01);
            sid.setIdentifierAuthority(identifier);
            return sid;
        }

        /// <summary>
        ///     Instances a SID instance of the given byte array.
        ///     @param src SID as byte array.
        ///     @return SID instance.
        /// </summary>
        public static SID parse(byte[] src)
        {
            ByteBuffer sddlBuffer = ByteBuffer.wrap(src);
            SID sid = new SID();
            sid.parse(sddlBuffer.asIntBuffer(), 0);
            return sid;
        }

        /// <summary>
        ///     Load the SID from the buffer returning the last SID segment position into the buffer.
        ///     @param buff source buffer.
        ///     @param start start loading position.
        ///     @return last loading position.
        /// </summary>
        private int parse(IntBuffer buff, int start)
        {
            int pos = start;

            // Check for a SID (http://msdn.microsoft.com/en-us/library/cc230371.aspx)
            byte[] sidHeader = NumberFacility.getBytes(buff.get(pos));

            // Revision(1 byte): An 8-bit unsigned integer that specifies the revision level of the SID.
            // This value MUST be set to 0x01.
            this.revision = sidHeader[0];

            //SubAuthorityCount (1 byte): An 8-bit unsigned integer that specifies the number of elements 
            //in the SubAuthority array. The maximum number of elements allowed is 15.
            int subAuthorityCount = NumberFacility.getInt(sidHeader[1]);

            // IdentifierAuthority (6 bytes): A SID_IDENTIFIER_AUTHORITY structure that indicates the 
            // authority under which the SID was created. It describes the entity that created the SID. 
            // The Identifier Authority value {0,0,0,0,0,5} denotes SIDs created by the NT SID authority.
            this.identifierAuthority = new byte[6];

            System.arraycopy(sidHeader, 2, this.identifierAuthority, 0, 2);

            pos++;
            System.arraycopy(NumberFacility.getBytes(buff.get(pos)), 0, this.identifierAuthority, 2, 4);

            // SubAuthority (variable): A variable length array of unsigned 32-bit integers that uniquely 
            // identifies a principal relative to the IdentifierAuthority. Its length is determined by 
            // SubAuthorityCount.
            for (var j = 0; j < subAuthorityCount; j++)
            {
                pos++;
                this.subAuthorities.Add(Hex.reverse(NumberFacility.getBytes(buff.get(pos))));
            }

            return pos;
        }

        /// <summary>
        ///     Gets revision level of the SID.
        ///     @return revision.
        /// </summary>
        public byte getRevision() => this.revision;

        /// <summary>
        ///     Gets sub-authority number: an 8-bit unsigned integer that specifies the number of elements in the SubAuthority
        ///     array. The maximum number of elements allowed is 15.
        ///     @return sub-authorities number.
        /// </summary>
        public int getSubAuthorityCount() => this.subAuthorities == null ? 0 : this.subAuthorities.Count > 15 ? 15 : this.subAuthorities.Count;

        /// <summary>
        ///     Gets identifier authority: 6 bytes describing the entity that created the SID.
        ///     @return identifier authority.
        /// </summary>
        public byte[] getIdentifierAuthority() => this.identifierAuthority == null ? null : this.identifierAuthority.Copy();

        /// <summary>
        ///     Gets sub-authorities: a list of unsigned 32-bit integers that uniquely identifies a principal
        ///     relative to the IdentifierAuthority.
        ///     @return sub-authorities.
        /// </summary>
        public ReadOnlyCollection<byte[]> getSubAuthorities()
        {
            var res = new List<byte[]>(this.getSubAuthorityCount());
            foreach (byte[] sub in this.subAuthorities)
            {
                if (sub != null)
                {
                    res.Add(sub.Copy());
                }
            }

            return new ReadOnlyCollection<byte[]>(res);
        }

        /// <summary>
        ///     Gets size of the SID byte array form.
        ///     @return size of SID byte aray form.
        /// </summary>
        public int getSize() => 8 + this.subAuthorities.Count * 4;

        /// <summary>
        ///     Sets revision level of the SID.
        ///     @param revision revision.
        ///     @return the current SID instance.
        /// </summary>
        public SID setRevision(byte revision)
        {
            this.revision = revision;
            return this;
        }

        /// <summary>
        ///     Sets idetifier authority: 6 bytes describing the entity that created the SID.
        ///     @param identifierAuthority identifier authority.
        ///     @return the current SID instance.
        /// </summary>
        public SID setIdentifierAuthority(byte[] identifierAuthority)
        {
            if (identifierAuthority == null || identifierAuthority.Length != 6)
            {
                throw new ArgumentOutOfRangeException("Invalid identifier authority");
            }

            this.identifierAuthority = identifierAuthority.Copy();
            return this;
        }

        /// <summary>
        ///     Adds sub-authority:a principal relative to the IdentifierAuthority.
        ///     @param sub sub-authority.
        ///     @return the current SID instance.
        /// </summary>
        public SID addSubAuthority(byte[] sub)
        {
            if (sub == null || sub.Length != 4)
            {
                throw new ArgumentOutOfRangeException("Invalid sub-authority to be added");
            }

            this.subAuthorities.Add(sub.Copy());
            return this;
        }

        /// <summary>
        ///     Serializes to byte array.
        ///     @return serialized SID.
        /// </summary>
        public byte[] toByteArray()
        {
            // variable content size depending on sub authorities number
            ByteBuffer buff = ByteBuffer.allocate(this.getSize());
            buff.put(this.revision);
            buff.put(NumberFacility.getBytes(this.subAuthorities.Count)[3]);
            buff.put(this.identifierAuthority);
            foreach (byte[] sub in this.subAuthorities)
            {
                buff.put(Hex.reverse(sub));
            }

            return buff.array();
        }

        public override string ToString()
        {
            StringBuilder bld = new StringBuilder();
            bld.Append("S-1-");

            if (this.identifierAuthority[0] == 0x00 && this.identifierAuthority[1] == 0x00)
            {
                bld.Append(NumberFacility.getUInt(
                    this.identifierAuthority[2], this.identifierAuthority[3], this.identifierAuthority[4], this.identifierAuthority[5]));
            }
            else
            {
                bld.Append(Hex.get(this.identifierAuthority));
            }

            if (this.subAuthorities.Count == 0)
            {
                bld.Append("-0");
            }
            else
            {
                foreach (byte[] sub in this.subAuthorities)
                {
                    bld.Append("-");
                    bld.Append(NumberFacility.getUInt(sub));
                }
            }

            return bld.ToString();
        }

        public override bool Equals(object sid)
        {
            if (!(sid is SID ext))
            {
                return false;
            }

            if (this.getSize() != ext.getSize())
            {
                return false;
            }

            if (this.getSubAuthorityCount() != ext.getSubAuthorityCount())
            {
                return false;
            }

            if (!this.getIdentifierAuthority().SequenceEqual(ext.getIdentifierAuthority()))
            {
                return false;
            }

            return !this.subAuthorities.Where((t, i) => !t.SequenceEqual(ext.getSubAuthorities()[i])).Any();
        }

        public override int GetHashCode()
        {
            var hash = 5;
            hash = 97 * hash + this.identifierAuthority.GetHashCode();
            hash = 97 * hash + this.subAuthorities.GetHashCode();
            return hash;
        }
    }
}