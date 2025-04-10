docker run -d \
  --name g-r-pdf2img \
  --restart always \
  -e RUNNER_NAME=g-r-pdf2img \
  -e RUNNER_WORKDIR=/tmp/g-r-pdf2img \
  -e RUNNER_GROUP=Default \
  -e RUNNER_TOKEN=ABPLEL4Y4A7ZNE5BKUH7EWTHQIQIE \
  -e REPO_URL=https://github.com/asmitul/pdf2img \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --cpus="0.5" \
  myoung34/github-runner:latest