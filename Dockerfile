#################
# Builder Image #
#################

FROM golang:alpine3.18 as builder

WORKDIR /go/src/oidc-authservice
# Download all dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download
# Copy in the code and compile
COPY *.go ./
COPY common common
COPY oidc oidc
COPY sessions sessions
COPY authenticators authenticators
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' -o /go/bin/oidc-authservice


#################
# Release Image #
#################

FROM alpine:3.18
RUN apk add --no-cache ca-certificates

ENV USER=authservice
ENV GROUP=authservice

# Add new user to run as
RUN addgroup -S -g 111 $GROUP && adduser -S -G $GROUP $USER
ENV APP_HOME=/home/$USER
WORKDIR $APP_HOME

# Copy in binary and give permissions
COPY --from=builder /go/bin/oidc-authservice $APP_HOME
COPY web $APP_HOME/web
RUN chmod +x $APP_HOME/oidc-authservice
RUN chown -R $USER:$GROUP $APP_HOME

USER $USER

ENTRYPOINT [ "./oidc-authservice" ]
