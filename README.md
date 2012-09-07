xenpagingtest
=============

Unit test for xen paging and mapping.

This unit test will spawn a dummy Xen VM, and show you how to set up xenpaging,
page out pages, and act as a dummy pager.

In parallel it will spawn a child process that will attempt to map the paged
out domain pages.

By trying a number of combinations of mapping patterns this will exercise the
advertised libxc and kernel privcmd interface for how paging-related errors are
handled in the mapping operations.

 -- Andres
