FROM golang:1.16
WORKDIR /go/src/app
COPY . .
COPY .netrc /root/.netrc
RUN chmod 600 /root/.netrc

RUN git config --global --add url."git@github.com:".insteadOf "https://github.com"
RUN GIT_TERMINAL_PROMPT=1 go get -d -v ./...

RUN go install -v ./...

CMD ["go","run","."]

