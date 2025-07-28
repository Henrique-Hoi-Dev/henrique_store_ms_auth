#!/bin/sh

if [ "$SET_CONTAINER_TIMEZONE" = "true" ]; then
    echo ${CONTAINER_TIMEZONE} >/etc/timezone && \
    ln -sf /usr/share/zoneinfo/${CONTAINER_TIMEZONE} /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata
    echo "Timezone: $CONTAINER_TIMEZONE"
else
    echo "Timezone não modificado"
fi

echo "Installing dependencies..."
npm install

echo "Start server ..."
# npm run dev
cross-env NODE_ENV=development && nodemon --inspect=0.0.0.0 server.js | npx pino-pretty

# echo "Create Tag image..."
# docker build -t api-node:v1 .

# echo "Apply kubernetes ..."
# kubectl apply -f ./kube
