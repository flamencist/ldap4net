using System;
using System.Collections.Generic;

namespace LdapForNetTests.Utils
{
    public class LambdaEqualityComparer<T> : IEqualityComparer<T>
    {
        private readonly Func<T, T, bool> _comparer;

        public LambdaEqualityComparer(Func<T, T, bool> comparer)
        {
            _comparer = comparer;
        }

        public bool Equals(T a, T b)
        {
            return _comparer(a, b);
        }

        public int GetHashCode(T a)
        {
            return a.GetHashCode();
        }
    }
}