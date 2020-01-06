using System;
using System.Runtime.InteropServices;
using System.Text;

namespace LdapForNet.Utils
{
    internal abstract class Encoder
    {
        public static Encoder Instance => CreateInstance();

        private static Encoder CreateInstance()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return new UnixEncoder();
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return new UnixEncoder();
            }
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return new WindowsEncoder();
            }
            throw new PlatformNotSupportedException();
        }

        public abstract string GetString(byte[] bytes);
        public abstract byte[] GetBytes(string str);
        public abstract IntPtr StringToPtr(string str);
        public abstract string PtrToString(IntPtr ptr);
    }

    internal class WindowsEncoder : Encoder {
        private static readonly Encoding Encoding = new UTF8Encoding();
        public override string GetString(byte[] bytes) => Encoding.GetString(bytes);

        public override byte[] GetBytes(string str) => Encoding.GetBytes(str);

        public override IntPtr StringToPtr(string str) => Marshal.StringToHGlobalUni(str);

        public override string PtrToString(IntPtr ptr) => Marshal.PtrToStringUni(ptr);
    }

    internal class UnixEncoder : Encoder
    {
        private static readonly Encoding Encoding = new ASCIIEncoding();
        public override string GetString(byte[] bytes) => Encoding.GetString(bytes);

        public override byte[] GetBytes(string str) => Encoding.GetBytes(str);

        public override IntPtr StringToPtr(string str) => Marshal.StringToHGlobalAnsi(str);

        public override string PtrToString(IntPtr ptr) => Marshal.PtrToStringAnsi(ptr);
    }
}
