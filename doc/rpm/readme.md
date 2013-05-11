-------------
Building RPMs
-------------

This spec file can be used to create binary RPM packages for Fedora, RedHat
Enterprise Linux, SWcientific Linux and other RPM based distributions.

To distinguish itself from the “normal” packages from the distribution
repositories the name was set to nginx-rtmp.

-----------------
Prebuild Packages
-----------------

Scientific Linux 6.x, Centos 6.x:
- [nginx-rtmp-1.2.8-3.el6.x86_64.rpm](https://docs.google.com/file/d/0B_bDfxNKSsxpSkp0NlVud3JfODA/edit?usp=sharing)
- [nginx-rtmp-debuginfo-1.2.8-3.el6.x86_64.rpm](https://docs.google.com/file/d/0B_bDfxNKSsxpUEtORXJHRTRHVkE/edit?usp=sharing)

Fedora 18:
- [nginx-rtmp-1.2.8-3.fc18.x86_64.rpm](https://docs.google.com/file/d/0B_bDfxNKSsxpd0QxQkc2ZEF3UUE/edit?usp=sharing)
- [nginx-rtmp-debuginfo-1.2.8-3.fc18.x86_64.rpm](https://docs.google.com/file/d/0B_bDfxNKSsxpUTFYc05PX0p1WjQ/edit?usp=sharing)

Fedora 17:
- [nginx-rtmp-1.2.8-3.fc17.x86_64.rpm](https://docs.google.com/file/d/0B_bDfxNKSsxpd29panlQNnIwUkE/edit?usp=sharing)
- [nginx-rtmp-debuginfo-1.2.8-3.fc17.x86_64.rpm](https://docs.google.com/file/d/0B_bDfxNKSsxpMWVGZDlXc0ZRMU0/edit?usp=sharing)


You can install these packages with:

	$ yum localinstall nginx-rtmp-...x86_64.rpm


---------------
Source Packages
---------------

Scientific Linux 6.x, Centos 6.x
- [nginx-rtmp-1.2.8-3.el6.src.rpm](https://docs.google.com/file/d/0B_bDfxNKSsxpb2prU1lFRTV1SFk/edit?usp=sharing)

Fedora 18:
- [nginx-rtmp-1.2.8-3.fc18.src.rpm](https://docs.google.com/file/d/0B_bDfxNKSsxpOWNHRkJCSjhTVEk/edit?usp=sharing)

Fedora 17:
- [nginx-rtmp-1.2.8-3.fc17.src.rpm](https://docs.google.com/file/d/0B_bDfxNKSsxpZmlwcGtTbnVCclk/edit?usp=sharing)

-------------------------
Building your own package
-------------------------

To learn how to build your own RPMs or to build it for other than the available
distributions have a look at:
- [How to create an RPM package](http://fedoraproject.org/wiki/How_to_create_an_RPM_package)
- [Packaging Guidelines](https://fedoraproject.org/wiki/Packaging:Guidelines)
