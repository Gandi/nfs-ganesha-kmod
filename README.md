FreeBSD kernel modules to implement required syscalls for userspace fileservers:
- very basic per-thread credentials (use them for other purposes at your own risk)  
- missing useful filehandle syscalls 

Tested on FreeBSD 11.  
To be used with [nfs-ganesha](https://github.com/nfs-ganesha/nfs-ganesha)
