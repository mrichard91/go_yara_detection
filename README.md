# Cross platform detection testing for golang binaries

## Usage
### Docker
1) Build the docker container `docker build . -t py311-yara`
2) Run the docker container with the repo directory mapped to the volme `docker run -p 8889:8888 -v $(pwd):/data py311-yara`

### Local python venv
0) Install golang from `https://go.dev/dl/`
1) Create a venv
2) Install deps `pip install -r requirements.txt`
3) Run Jupyterlab `jupyter lab` and open the notebooks
