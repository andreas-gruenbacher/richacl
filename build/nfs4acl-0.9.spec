Summary: NFSv4 ACL Utilities
Name: nfs4acl
Version: 0.9
Release: 20080229T1159
License: GPL
Distribution: SGI InfiniteStorage Software Platform
Packager: Silicon Graphics, Inc. <http://www.sgi.com/>
Vendor: SUSE LINUX Products GmbH, Nuernberg, Germany
Group: System/Base
Source: nfs4acl-0.9.tar.gz
Patch1: gnb-nfs4acl-add-install-target
URL: http://www.sgi.com/
BuildRoot: %{_tmppath}/%{name}-root

%description
Utilities for getting and setting NFSv4 style ACLs on those
filesystems which support them, such as NFSv4, XFS and ext3.

%prep
%setup
%patch1 -p1

%build
# nfs4acl doesn't have automake et al yet
make prefix=/usr all

%install
make prefix=/usr DESTDIR=$RPM_BUILD_ROOT install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{_sbindir}/*
%{_libdir}/*
%{_includedir}/nfs4acl
%{_datadir}/%name/test
