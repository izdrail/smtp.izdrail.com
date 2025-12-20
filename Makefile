#!/usr/bin/make -f

# Define variables
IMAGE_PROD=izdrail/smtp.izdrail.com:latest
DOCKERFILE=Dockerfile
DOCKER_COMPOSE_FILE=docker-compose.yml
CONTAINER_NAME=smtp-verifier

build:
	docker build \
		-t $(IMAGE_PROD) \
		--build-arg CACHEBUST=$$(date +%s) \
		-f $(DOCKERFILE) \
		.

build-multiarch:
	docker buildx build \
		--platform linux/amd64 \
		-t $(IMAGE_PROD) \
		--progress=plain \
		--build-arg CACHEBUST=$$(date +%s) \
		-f $(DOCKERFILE) \
		.

prod:
	docker-compose -f $(DOCKER_COMPOSE_FILE) up -d --remove-orphans

down:
	docker-compose -f $(DOCKER_COMPOSE_FILE) down

shell:
	docker exec -it $(CONTAINER_NAME) /bin/sh

publish:
	docker push $(IMAGE_PROD)

logs:
	docker logs -f $(CONTAINER_NAME)

restart:
	docker-compose -f $(DOCKER_COMPOSE_FILE) restart

prune:
	docker system prune -f --volumes

clean:
	-docker-compose -f $(DOCKER_COMPOSE_FILE) down --rmi all --volumes --remove-orphans
	-docker system prune -f --volumes
