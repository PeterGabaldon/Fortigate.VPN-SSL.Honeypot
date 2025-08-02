FROM alpine:3.16
#
# Include dist
COPY dist/ /root/dist/
#
# Get and install dependencies & packages
RUN apk -U --no-cache add \
      nginx \
      nginx-mod-http-headers-more && \
#
## Setup T-Pot Landing Page, Eleasticvue, Cyberchef 
    #cp -R /root/dist/html/* /var/lib/nginx/html/ && \
#
## Change ownership, permissions
    chown root:www-data -R /var/lib/nginx/html && \
    chmod 755 -R /var/lib/nginx/html && \
#
## Add Nginx / T-Pot specific configs
    rm -rf /etc/nginx/conf.d/* /usr/share/nginx/html/* && \
    mkdir -p /etc/nginx/conf.d && \
    cp /root/dist/conf/nginx.conf /etc/nginx/ && \
    mkdir -p /etc/nginx/cert/ && \
    cp /root/dist/conf/ssl/nginx.crt /etc/nginx/cert/ && \
    cp /root/dist/conf/ssl/nginx.key /etc/nginx/cert/ && \
    cp /root/dist/conf/ssl/dhparam2048.pem /etc/nginx/cert/ && \
    cp /root/dist/conf/honey.conf /etc/nginx/conf.d/ && \
#
# Clean up
    rm -rf /root/* && \
    rm -rf /var/cache/apk/*
#
# Start nginx
CMD nginx -g 'daemon off;'
