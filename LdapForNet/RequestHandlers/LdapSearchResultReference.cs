using System;

namespace LdapForNet.RequestHandlers
{
    public class LdapSearchResultReference
    {
        private readonly Uri[] _resultReferences;
        private readonly DirectoryControl[] _resultControls;

        internal LdapSearchResultReference(Uri[] uris, DirectoryControl[] controls)
        {
            _resultReferences = uris;
            _resultControls = controls;
        }

        public Uri[] Reference
        {
            get
            {
                if (_resultReferences == null)
                {
                    return Array.Empty<Uri>();
                }

                var tempUri = new Uri[_resultReferences.Length];
                for (var i = 0; i < _resultReferences.Length; i++)
                {
                    tempUri[i] = new Uri(_resultReferences[i].AbsoluteUri);
                }
                return tempUri;
            }
        }

        public DirectoryControl[] Controls
        {
            get
            {
                if (_resultControls == null)
                {
                    return Array.Empty<DirectoryControl>();
                }

                var controls = new DirectoryControl[_resultControls.Length];
                for (var i = 0; i < _resultControls.Length; i++)
                {
                    controls[i] = new DirectoryControl(_resultControls[i].Type, _resultControls[i].GetValue(), _resultControls[i].IsCritical, _resultControls[i].ServerSide);
                }
                DirectoryControl.TransformControls(controls);
                return controls;
            }
        }
    }
}