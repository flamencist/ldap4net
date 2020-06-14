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
using System.IO;
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
        public static SID NewInstance(byte[] identifier)
        {
            SID sid = new SID();
            sid.SetRevision(0x01);
            sid.SetIdentifierAuthority(identifier);
            return sid;
        }

        /// <summary>
        ///     Instances a SID instance of the given byte array.
        ///     @param src SID as byte array.
        ///     @return SID instance.
        /// </summary>
        public static SID Parse(byte[] src)
        {
            using var ms = new MemoryStream(src);
            using var sddlBuffer = new BinaryReader(ms);
            SID sid = new SID();
            sid.Parse(sddlBuffer, 0);
            return sid;
        }

        /// <summary>
        ///     Load the SID from the buffer returning the last SID segment position into the buffer.
        ///     @param buff source buffer.
        ///     @param start start loading position.
        ///     @return last loading position.
        /// </summary>
        public void Parse(BinaryReader buff, long? start = null)
        {
            if (start != null)
            {
                buff.BaseStream.Seek(start.Value, SeekOrigin.Begin);
            }

            // Check for a SID (http://msdn.microsoft.com/en-us/library/cc230371.aspx)
            byte[] sidHeader = NumberFacility.GetBytes(buff.ReadInt32());

            // Revision(1 byte): An 8-bit unsigned integer that specifies the revision level of the SID.
            // This value MUST be set to 0x01.
            this.revision = sidHeader[0];

            //SubAuthorityCount (1 byte): An 8-bit unsigned integer that specifies the number of elements 
            //in the SubAuthority array. The maximum number of elements allowed is 15.
            int subAuthorityCount = NumberFacility.GetInt(sidHeader[1]);

            // IdentifierAuthority (6 bytes): A SID_IDENTIFIER_AUTHORITY structure that indicates the 
            // authority under which the SID was created. It describes the entity that created the SID. 
            // The Identifier Authority value {0,0,0,0,0,5} denotes SIDs created by the NT SID authority.
            this.identifierAuthority = new byte[6];
            this.identifierAuthority[0] = sidHeader[2];
            this.identifierAuthority[1] = sidHeader[3];
            for (int i = 0; i < 4; i++)
            {
                this.identifierAuthority[i + 2] = buff.ReadByte();
            }

            // SubAuthority (variable): A variable length array of unsigned 32-bit integers that uniquely 
            // identifies a principal relative to the IdentifierAuthority. Its length is determined by 
            // SubAuthorityCount.
            for (var j = 0; j < subAuthorityCount; j++)
            {
                this.subAuthorities.Add(Hex.Reverse(NumberFacility.GetBytes(buff.ReadInt32())));
            }
        }

        /// <summary>
        ///     Gets revision level of the SID.
        ///     @return revision.
        /// </summary>
        public byte GetRevision() => this.revision;

        /// <summary>
        ///     Gets sub-authority number: an 8-bit unsigned integer that specifies the number of elements in the SubAuthority
        ///     array. The maximum number of elements allowed is 15.
        ///     @return sub-authorities number.
        /// </summary>
        public int GetSubAuthorityCount() => this.subAuthorities == null ? 0 : this.subAuthorities.Count > 15 ? 15 : this.subAuthorities.Count;

        /// <summary>
        ///     Gets identifier authority: 6 bytes describing the entity that created the SID.
        ///     @return identifier authority.
        /// </summary>
        public byte[] GetIdentifierAuthority() => this.identifierAuthority == null ? null : this.identifierAuthority.Copy();

        /// <summary>
        ///     Gets sub-authorities: a list of unsigned 32-bit integers that uniquely identifies a principal
        ///     relative to the IdentifierAuthority.
        ///     @return sub-authorities.
        /// </summary>
        public ReadOnlyCollection<byte[]> GetSubAuthorities()
        {
            var res = new List<byte[]>(this.GetSubAuthorityCount());
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
        public int GetSize() => 8 + this.subAuthorities.Count * 4;

        /// <summary>
        ///     Sets revision level of the SID.
        ///     @param revision revision.
        ///     @return the current SID instance.
        /// </summary>
        public SID SetRevision(byte revision)
        {
            this.revision = revision;
            return this;
        }

        /// <summary>
        ///     Sets idetifier authority: 6 bytes describing the entity that created the SID.
        ///     @param identifierAuthority identifier authority.
        ///     @return the current SID instance.
        /// </summary>
        public SID SetIdentifierAuthority(byte[] identifierAuthority)
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
        public SID AddSubAuthority(byte[] sub)
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
        public byte[] ToByteArray()
        {
            // variable content size depending on sub authorities number
            using var ms = new MemoryStream(this.GetSize());
            var buff = new BinaryWriter(ms);
            buff.Write(this.revision);
            buff.Write(NumberFacility.GetBytes(this.subAuthorities.Count)[3]);
            buff.Write(this.identifierAuthority);
            foreach (byte[] sub in this.subAuthorities)
            {
                buff.Write(Hex.Reverse(sub));
            }

            return ms.ToArray();
        }

        public override string ToString()
        {
            StringBuilder bld = new StringBuilder();
            bld.Append("S-1-");

            if (this.identifierAuthority[0] == 0x00 && this.identifierAuthority[1] == 0x00)
            {
                bld.Append(NumberFacility.GetUInt(
                    this.identifierAuthority[2], this.identifierAuthority[3], this.identifierAuthority[4], this.identifierAuthority[5]));
            }
            else
            {
                bld.Append(Hex.Get(this.identifierAuthority));
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
                    bld.Append(NumberFacility.GetUInt(sub));
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

            if (this.GetSize() != ext.GetSize())
            {
                return false;
            }

            if (this.GetSubAuthorityCount() != ext.GetSubAuthorityCount())
            {
                return false;
            }

            if (!this.GetIdentifierAuthority().SequenceEqual(ext.GetIdentifierAuthority()))
            {
                return false;
            }

            return !this.subAuthorities.Where((t, i) => !t.SequenceEqual(ext.GetSubAuthorities()[i])).Any();
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