# Pull base image.
FROM ubuntu:xenial

# Install Nginx.
RUN \
  apt-get -q -y update && \
  apt-get -q -y install build-essential libpcre3 \
  cron logrotate make \
  zlib1g-dev curl pgp yasm \
  libpcre3-dev libssl-dev unzip wget nano libav-tools ffmpeg

# rebuilding
RUN cd /root && \
  wget http://nginx.org/download/nginx-1.9.2.tar.gz
  
COPY ./* /root/nginx-rtmp-module-master/
  
RUN cd /root && \
  tar -zxvf nginx-1.9.2.tar.gz
  
RUN cd /root/nginx-1.9.2 && \
  ./configure --add-module=../nginx-rtmp-module-master && \
  make && \
  make install

# Expose ports.
EXPOSE 80
EXPOSE 443
EXPOSE 1395 
  
# Define working directory.
WORKDIR /usr/local/nginx

# Define default command.
CMD ["/usr/local/nginx/sbin/nginx","-c","/usr/local/nginx/conf/nginx.conf"]
