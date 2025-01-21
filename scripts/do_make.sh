./auto/configure --prefix=/home/hzh/workspace/nginx/bin --with-http_ssl_module --with-debug --with-cc-opt='-g -o0'
sudo make -j8 CFLAGS="-g -oO"
# make install