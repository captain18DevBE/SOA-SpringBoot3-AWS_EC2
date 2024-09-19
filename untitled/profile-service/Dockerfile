FROM neo4j:latest

# Create a volume for Neo4j data
VOLUME /data

ENTRYPOINT ["top", "-b"]

## For Docker CLI
# docker pull neo4j:latest
# docker volume create neo4j_data

# docker run -d \
#   --name neo4j-instance \
#   -p 7474:7474 -p 7687:7687 \
#   -v neo4j_data:/data \
#   -e NEO4J_AUTH=neo4j/yourpassword \
#   neo4j:latest

# docker run -d --name neo4j:latest -p 7474:7474 -p 7687:7687 -v neo4j_data:/data neo4j

### Check the container is running
# docker ps
# docker logs neo4j-instance
# docker stop neo4j-profiles-service to stop the container


## For Docker Compose
# version: '3'

# services:
#   neo4j:
#     build: .
#     ports:
#       - "7474:7474"  # HTTP
#       - "7687:7687"  # Bolt
#     volumes:
#       - neo4j_data:/data
#     environment:
#       - NEO4J_AUTH=neo4j/yourpassword  # Set your desired password

# volumes:
#   neo4j_data: