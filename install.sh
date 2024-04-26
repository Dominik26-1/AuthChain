#!/bin/bash

# Install curl if it's not already installed
if ! command -v curl &> /dev/null
then
    echo "curl nie je nainštalovaný. Pokúšam sa nainštalovať..."
    sudo apt-get update
    sudo apt-get install -y curl
else
    echo "curl je už nainštalovaný."
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null
then
    echo "Docker nie je nainštalovaný. Pokúšam sa nainštalovať..."
    sudo apt-get update
    sudo apt-get install -y docker.io
    sudo systemctl start docker
    sudo systemctl enable docker
else
    echo "Docker je už nainštalovaný."
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null
then
    echo "Docker Compose nie je nainštalovaný. Pokúšam sa nainštalovať..."
    sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
else
    echo "Docker Compose je už nainštalovaný."
fi

docker service rm my_stack_postgres
docker service rm my_stack_flask
docker service rm my_stack_nginx


docker-compose down

# Inicializácia Docker Swarmu, ak nie je aktívny
if ! docker info | grep -q "Swarm: active"; then
    echo "Inicializujem Docker Swarm..."
    sudo docker swarm init
else
    echo "Docker Swarm je už aktívny."
fi

# Overenie, či secret existuje, a jeho odstránenie
if docker secret ls | grep -q secret1; then
    echo "Secret my_secret_name existuje. Pokúšam sa ho odstrániť..."
    docker secret rm secret1
    docker secret rm secret2
    docker secret rm secret3
else
    echo "Secret my_secret_name neexistuje. Žiadna akcia nie je potrebná."
fi

# Spustenie Python skriptu
./device_id_loader

# Spustenie Docker Compose
docker build -t authchain:latest ./Flask
#docker load -i authchain.tar
# Namiesto docker-compose up -d
export $(cat .env | xargs) && docker stack deploy -c docker-compose.yml my_stack