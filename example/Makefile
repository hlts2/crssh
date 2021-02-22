
NAME ?= ghcr.io/linuxserver/openssh-server

.PHONY: ssh/server/start
ssh/server/start:
	docker run -d \
    --name=openssh-server \
    --hostname=openssh-server \
    -e SUDO_ACCESS=true \
    -e PASSWORD_ACCESS=true \
    -e USER_PASSWORD=password \
    -e USER_NAME=linuxserver.io \
    -p 2222:2222 \
    ${NAME}
