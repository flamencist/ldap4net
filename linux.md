# Linux: Symlinks for `libldap.so.2` and `liblber.so.2`

After installing the OpenLDAP client libraries for Linux, you must ensure that the appropriate symlinks `libldap.so.2` and `liblber.so.2` exist in your library directory, which is usually `/lib` or `/usr/lib`.

They're usually created by default when installing the OpenLDAP client libraries package and refer directly or indirectly to the latest version of the corresponding library located in the same directory, for example:

```sh
root@linux ~ % ls -l /usr/lib/libldap.so.2
lrwxrwxrwx 1 root root 10 Jul 18  2021 /usr/lib/libldap.so.2 -> libldap.so
root@linux ~ % ls -l /usr/lib/libldap.so
lrwxrwxrwx 1 root root 21 Jul 18  2021 /usr/lib/libldap.so -> libldap_r-2.4.so.2.11.7
root@linux ~ % ls -l /usr/lib/liblber.so.2
lrwxrwxrwx 1 root root 10 Jul 18  2021 /usr/lib/liblber.so.2 -> liblber.so
root@linux ~ % ls -l /usr/lib/liblber.so
lrwxrwxrwx 1 root root 21 Jul 18  2021 /usr/lib/liblber.so -> liblber-2.4.so.2.11.7
```

If these symlinks do not exist, you can create direct links to the corresponding library using the following commands:

```sh
root@linux ~ % ln -s /usr/lib/libldap-2.X.so.2.Y.Z /usr/lib/libldap.so.2
root@linux ~ % ln -s /usr/lib/liblber-2.X.so.2.Y.Z /usr/lib/liblber.so.2
```

If you're using `2.4` or older version of `libldap`, the symlink must point to `libldap_r`, the threaded version of the library,
otherwise async methods might cause unpredictable errors. Starting with `2.5` `libldap` is multi-threaded by default.