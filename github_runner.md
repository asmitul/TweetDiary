docker run -d \
  --name g-r-diary \
  --restart always \
  -e RUNNER_NAME=g-r-diary \
  -e RUNNER_WORKDIR=/tmp/g-r-diary \
  -e RUNNER_GROUP=Default \
  -e RUNNER_TOKEN=ABPLEL34CWZHFNSF6DQP4QDH66NRI \
  -e REPO_URL=https://github.com/asmitul/diary \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --cpus="3" \
  myoung34/github-runner:latest