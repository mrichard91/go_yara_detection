FROM python:3.11-bookworm

EXPOSE 8888/tcp

# Install any dependencies
RUN apt-get update && apt-get install -y build-essential cmake openssl golang yara

COPY requirements.txt .
RUN pip install -r requirements.txt

VOLUME ["/data"]

# Set the working directory in the container
WORKDIR /data

# Specify the command to run on container start
ENTRYPOINT ["jupyter", "lab", "--ip=0.0.0.0", "--allow-root"]
