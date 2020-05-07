namespace LdapForNet.Utils
{
    internal static class HexEscaper
    {
        internal static string Escape(string hex)
        {
            var chars = new char[(hex.Length / 2) * 3];
            for (var i = 0; i < hex.Length / 2; i++)
            {
                chars[3 * i] = '\\';
                chars[3 * i + 1] = hex[2 * i];
                chars[3 * i + 2] = hex[2 * i + 1];
            }

            return new string(chars);
        }
    }
}