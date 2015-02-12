## modified nginx-rtmp-module using [rabbit-c](https://github.com/alanxz/rabbitmq-c) for HLS
adds new message on each HLS file creation for further processing
it pushes message with these details "`Application Name` `filename (without application token)` `duration` `filecreation time in UNIX`"
i.e "`u1cam1 3031 2.5 1423724678`"

### Configuration
change these variables as per requirement in hls/ngx_rtmp_hls_module.c:858

    hostname = "localhost";
    int port = 5672;
    exchange = "exchangename";
    routingkey = "Queue";
### Build

cd to NGINX source directory & run this:

    ./configure --add-module=/path/to/nginx-rtmp-module
    add "-lrabbitmq" after "-lpthread" in objs/Makefile
    make
    make install

For installtion in window move threads.h file form win folder to main folder

### TODO
* move configration to nginx.conf
* support other features of rabbit-c
* multi-routingkey support per application
* support of other types (DASH etc)
