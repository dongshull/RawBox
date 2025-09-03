FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o rawbox .

FROM alpine:latest

# 安装tzdata以支持时区设置
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/rawbox ./rawbox
COPY --from=builder /app/error_pages ./error_pages
RUN chmod +x ./rawbox

# 设置默认时区
ENV TZ=Asia/Shanghai

EXPOSE 8080
ENTRYPOINT ["/app/rawbox"]