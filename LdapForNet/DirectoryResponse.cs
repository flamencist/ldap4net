using System;
using System.Collections.Generic;
using LdapForNet.RequestHandlers;

namespace LdapForNet
{
    public abstract class DirectoryResponse
    {
        private DirectoryControl[] _directoryControls;
        private Uri[] _directoryReferral;
        public virtual Native.Native.ResultCode ResultCode { get; internal set; }

        public virtual string ErrorMessage { get; internal set; }
        
        public virtual DirectoryControl[] Controls
        {
            get
            {
                if (_directoryControls == null)
                {
                    return Array.Empty<DirectoryControl>();
                }

                var tempControls = new DirectoryControl[_directoryControls.Length];
                for (int i = 0; i < _directoryControls.Length; i++)
                {
                    tempControls[i] = new DirectoryControl(_directoryControls[i].Type, _directoryControls[i].GetValue(), _directoryControls[i].IsCritical, _directoryControls[i].ServerSide);
                }
                DirectoryControl.TransformControls(tempControls);
                return tempControls;
            }
            internal set => _directoryControls = value;
        }
        
        public virtual Uri[] Referral
        {
            get
            {
                if (_directoryReferral == null)
                {
                    return Array.Empty<Uri>();
                }

                var tempReferral = new Uri[_directoryReferral.Length];
                for (int i = 0; i < _directoryReferral.Length; i++)
                {
                    tempReferral[i] = new Uri(_directoryReferral[i].AbsoluteUri);
                }
                return tempReferral;
            }
            internal set => _directoryReferral = value;
        }
        
        public virtual string MatchedDN { get; internal set; }
    }
    
    public class SearchResponse : DirectoryResponse
    {
        public List<LdapEntry> Entries { get; internal set; } = new List<LdapEntry>();
        public List<LdapSearchResultReference> References { get; } = new List<LdapSearchResultReference>();
    }

    public class AddResponse : DirectoryResponse
    {
        
    }
    
    public class ModifyResponse : DirectoryResponse
    {
        
    }
    
    public class ModifyDNResponse : DirectoryResponse
    {
        
    }
    
    public class DeleteResponse : DirectoryResponse
    {
        
    }
    
    public class ExtendedResponse : DirectoryResponse
    {
        private byte[] _value;

        public string ResponseName { get; internal set; }

        public byte[] ResponseValue
        {
            get
            {
                if (_value == null)
                {
                    return Array.Empty<byte>();
                }

                byte[] tmpValue = new byte[_value.Length];
                for (int i = 0; i < _value.Length; i++)
                {
                    tmpValue[i] = _value[i];
                }

                return tmpValue;
            }
            internal set => _value = value;
        }
    }

    public class CompareResponse : DirectoryResponse
    {
        
    }
}