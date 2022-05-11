ECHO OFF
ECHO Building server image
docker-compose -f .\docker-compose.yml build
ECHO Starting docker container
docker-compose -f .\docker-compose.yml up -d