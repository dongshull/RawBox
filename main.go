package main

import (
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	publicDir  = "public"
	privateDir = "private"
	logDir     = "log"
	// 添加错误页面目录常量
	errorPagesDir = "error_pages"
)

var (
	dataDir = "./data"
	port    = 8080
	tokens  = make(map[string]bool)
	tokenMu sync.RWMutex
)

// UARules 定义UA规则结构
type UARules struct {
	Whitelist []string `json:"whitelist"`
	Blacklist []string `json:"blacklist"`
}

var (
	uaRules   UARules
	uaRulesMu sync.RWMutex
)

// responseWriterDelegator 用于捕获HTTP响应状态码
type responseWriterDelegator struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// WriteHeader 重写WriteHeader方法以捕获状态码
func (r *responseWriterDelegator) WriteHeader(code int) {
	r.statusCode = code
	r.written = true
	r.ResponseWriter.WriteHeader(code)
}

// Write 重写Write方法以捕获默认状态码（200）
func (r *responseWriterDelegator) Write(b []byte) (int, error) {
	if !r.written {
		// 如果还没有写入状态码，设置默认值为200
		r.statusCode = http.StatusOK
		r.written = true
		// 确保在首次写入时也发送状态码
		r.ResponseWriter.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}

// GetStatusCode 获取状态码
func (r *responseWriterDelegator) GetStatusCode() int {
	if !r.written {
		return http.StatusOK
	}
	return r.statusCode
}

// loggingMiddleware 记录请求日志的中间件
func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 创建responseWriterDelegator以捕获状态码
		delegator := &responseWriterDelegator{ResponseWriter: w, statusCode: http.StatusOK}
		
		// 记录请求开始时间
		startTime := time.Now()
		
		// 处理请求
		next(delegator, r)
		
		// 记录日志（在请求处理完成后记录，使用实际的状态码）
		logRequest(r, delegator.GetStatusCode(), startTime)
	}
}

// logRequest 记录请求日志到文件
func logRequest(r *http.Request, statusCode int, startTime time.Time) {
	// 确保日志目录存在
	logPath := filepath.Join(dataDir, logDir)
	if err := os.MkdirAll(logPath, 0755); err != nil {
		log.Printf("Failed to create log directory: %v", err)
		return
	}

	// 生成日志文件名
	logFileName := fmt.Sprintf("%s-RawBox-log.txt", time.Now().Format("2006-01-02"))
	logFilePath := filepath.Join(logPath, logFileName)

	// 构建日志条目
	logEntry := fmt.Sprintf("%s, %s, %s, %s, %d\n",
		startTime.Format("2006-01-02 15:04:05"),
		getRealIP(r),
		r.URL.Path,
		r.UserAgent(),
		statusCode)

	// 写入日志文件
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("Failed to open log file: %v", err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(logEntry); err != nil {
		log.Printf("Failed to write to log file: %v", err)
	}
	
	// 同时在控制台输出简化的访问日志（使用fmt.Printf避免重复时间戳）
	fmt.Printf("%s, %s, %s, %s, %d\n",
		startTime.Format("2006/01/02 15:04:05"),
		getRealIP(r),
		r.URL.Path,
		r.UserAgent(),
		statusCode)
}

// getRealIP 获取客户端真实IP地址
func getRealIP(r *http.Request) string {
	// 检查常见的代理头
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// X-Forwarded-For可能包含多个IP，取第一个
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 检查其他可能的头
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// 如果没有代理头，则直接使用RemoteAddr
	ip := r.RemoteAddr
	// 移除端口号（如果存在）
	if colonIndex := strings.LastIndex(ip, ":"); colonIndex != -1 {
		ip = ip[:colonIndex]
	}
	
	return ip
}

func main() {
	log.Println("RawBox starting...")

	// 检查环境变量
	if envDataDir := os.Getenv("DATA_DIR"); envDataDir != "" {
		dataDir = envDataDir
	}
	
	// 检查端口环境变量
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 && p <= 65535 {
			port = p
		} else {
			log.Printf("Invalid PORT environment variable: %s, using default port %d", envPort, port)
		}
	}

	// 初始化目录
	initDir()

	// 加载配置
	loadTokens()
	loadUARules()

	// 设置HTTP路由
	http.HandleFunc("/", loggingMiddleware(handler))

	// 启动HTTP服务
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Server listening on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// initDir 初始化目录结构
func initDir() {
	// 检查/data目录是否存在
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		log.Printf("Data directory %s does not exist, creating...", dataDir)
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			log.Fatalf("Failed to create data directory: %v", err)
		}
	} else if err != nil {
		log.Printf("Error checking data directory: %v", err)
		if os.IsPermission(err) {
			log.Fatalf("Permission denied when accessing data directory %s. Please check mount permissions.", dataDir)
		}
	}

	// 确保public、private、log和error_pages目录存在，无论数据目录是否为空
	log.Println("Ensuring public, private, log and error_pages directories exist")

	// 创建公开目录
	publicPath := filepath.Join(dataDir, publicDir)
	if err := os.MkdirAll(publicPath, 0755); err != nil {
		log.Printf("Failed to create public directory: %v", err)
		if os.IsPermission(err) {
			log.Fatalf("Permission denied when creating %s. Please ensure the volume is mounted as writable.", publicPath)
		}
	}

	// 创建私密目录
	privatePath := filepath.Join(dataDir, privateDir)
	if err := os.MkdirAll(privatePath, 0755); err != nil {
		log.Printf("Failed to create private directory: %v", err)
		if os.IsPermission(err) {
			log.Fatalf("Permission denied when creating %s. Please ensure the volume is mounted as writable.", privatePath)
		}
	}

	// 创建日志目录
	logPath := filepath.Join(dataDir, logDir)
	if err := os.MkdirAll(logPath, 0755); err != nil {
		log.Printf("Failed to create log directory: %v", err)
		if os.IsPermission(err) {
			log.Fatalf("Permission denied when creating %s. Please ensure the volume is mounted as writable.", logPath)
		}
	}

	// 复制错误页面到数据目录
	// copyErrorPagesIfNeeded(errorPagesPath)

	log.Println("Directory structure checked/created successfully")
	
	// 验证目录是否真正创建
	if _, err := os.Stat(publicPath); os.IsNotExist(err) {
		log.Fatalf("Failed to verify public directory creation: %v", err)
	}
	
	if _, err := os.Stat(privatePath); os.IsNotExist(err) {
		log.Fatalf("Failed to verify private directory creation: %v", err)
	}
	
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		log.Fatalf("Failed to verify log directory creation: %v", err)
	}
	
	log.Println("All directories verified successfully")
}

// serveErrorPage 提供自定义错误页面
func serveErrorPage(w http.ResponseWriter, r *http.Request, errorCode int) {
	// 构建错误页面文件路径（使用镜像内部的error_pages目录）
	errorPagePath := filepath.Join(errorPagesDir, fmt.Sprintf("%d.html", errorCode))
	
	// 检查错误页面文件是否存在
	if _, err := os.Stat(errorPagePath); err == nil {
		// 如果存在，提供自定义错误页面
		http.ServeFile(w, r, errorPagePath)
		return
	}
	
	// 如果自定义错误页面不存在，使用默认错误处理
	var errorMsg string
	switch errorCode {
	case http.StatusUnauthorized:
		errorMsg = "Unauthorized: Invalid or missing token"
	case http.StatusForbidden:
		errorMsg = "Forbidden: User agent not allowed"
	case http.StatusNotFound:
		errorMsg = "File not found"
	case http.StatusInternalServerError:
		errorMsg = "Internal server error"
	default:
		errorMsg = http.StatusText(errorCode)
	}
	
	http.Error(w, errorMsg, errorCode)
}

// handler 处理所有HTTP请求
func handler(w http.ResponseWriter, r *http.Request) {
	// 获取请求路径和API token
	path := strings.TrimPrefix(r.URL.Path, "/")
	token := r.URL.Query().Get("api")
	
	// 记录请求开始时间
	startTime := time.Now()

	// 检查是否请求日志路径
	if path == "log" {
		// 检查是否提供了API token
		if token == "" {
			logRequest(r, http.StatusUnauthorized, startTime)
			serveErrorPage(w, r, http.StatusUnauthorized)
			return
		}
		
		// 验证API token是否有效
		if !tokenCheck(token) {
			logRequest(r, http.StatusUnauthorized, startTime)
			serveErrorPage(w, r, http.StatusUnauthorized)
			return
		}
		
		logRequest(r, http.StatusOK, startTime)
		serveLogs(w, r)
		return
	}

	// 检查UA
	if !uaCheck(r.UserAgent()) {
		logRequest(r, http.StatusForbidden, startTime)
		serveErrorPage(w, r, http.StatusForbidden)
		return
	}

	// 确定文件应该在哪个目录中
	var dir string
	if token != "" {
		// 如果提供了token，则访问私有目录（无论token是否有效）
		dir = privateDir
	} else {
		// 默认访问公共目录
		dir = publicDir
	}

	// 构建完整文件路径
	fullPath := filepath.Join(dataDir, dir, path)

	// 检查文件是否存在
	fileInfo, err := os.Stat(fullPath)
	if os.IsNotExist(err) {
		// 先验证token
		if token != "" && !tokenCheck(token) {
			logRequest(r, http.StatusUnauthorized, startTime)
			serveErrorPage(w, r, http.StatusUnauthorized)
			return
		}
		logRequest(r, http.StatusNotFound, startTime)
		serveErrorPage(w, r, http.StatusNotFound)
		return
	} else if err != nil {
		logRequest(r, http.StatusInternalServerError, startTime)
		serveErrorPage(w, r, http.StatusInternalServerError)
		return
	}

	// 不允许访问目录
	if fileInfo.IsDir() {
		logRequest(r, http.StatusForbidden, startTime)
		serveErrorPage(w, r, http.StatusForbidden)
		return
	}

	// 检查token是否有效（如果提供了token）
	if token != "" && !tokenCheck(token) {
		logRequest(r, http.StatusUnauthorized, startTime)
		serveErrorPage(w, r, http.StatusUnauthorized)
		return
	}

	// 直接提供原始文件内容
	logRequest(r, http.StatusOK, startTime)
	serveRaw(w, r, fullPath)
}

// serveLogs 提供日志文件列表和内容
func serveLogs(w http.ResponseWriter, r *http.Request) {
	// 检查是否指定了特定的日志文件
	logFile := r.URL.Query().Get("file")
	
	// 构建日志目录路径
	logPath := filepath.Join(dataDir, logDir)
	
	// 如果指定了特定的日志文件
	if logFile != "" {
		// 防止路径遍历攻击
		if strings.Contains(logFile, "..") {
			http.Error(w, "Invalid file path", http.StatusBadRequest)
			return
		}
		
		// 构建完整文件路径
		fullPath := filepath.Join(logPath, logFile)
		
		// 检查文件是否存在且在日志目录中
		relPath, err := filepath.Rel(logPath, fullPath)
		if err != nil || strings.Contains(relPath, "..") {
			http.Error(w, "Invalid file path", http.StatusBadRequest)
			return
		}
		
		// 检查文件是否存在
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			http.Error(w, "Log file not found", http.StatusNotFound)
			return
		}
		
		// 提供日志文件内容
		http.ServeFile(w, r, fullPath)
		return
	}
	
	// 如果没有指定特定的日志文件，列出所有日志文件
	files, err := os.ReadDir(logPath)
	if err != nil {
		http.Error(w, "Failed to read log directory", http.StatusInternalServerError)
		return
	}
	
	// 创建HTML页面显示日志文件列表
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<!DOCTYPE html>\n<html>\n<head>\n")
	fmt.Fprintf(w, "<meta charset=\"utf-8\">\n")
	fmt.Fprintf(w, "<title>RawBox 日志文件</title>\n")
	fmt.Fprintf(w, "<style>\n")
	fmt.Fprintf(w, "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; margin: 2rem; }\n")
	fmt.Fprintf(w, "h1 { color: #333; }\n")
	fmt.Fprintf(w, "ul { list-style-type: none; padding: 0; }\n")
	fmt.Fprintf(w, "li { margin: 0.5rem 0; }\n")
	fmt.Fprintf(w, "a { text-decoration: none; color: #0366d6; }\n")
	fmt.Fprintf(w, "a:hover { text-decoration: underline; }\n")
	fmt.Fprintf(w, "</style>\n")
	fmt.Fprintf(w, "</head>\n<body>\n")
	fmt.Fprintf(w, "<h1>RawBox 日志文件</h1>\n")
	fmt.Fprintf(w, "<ul>\n")
	
	// 添加返回首页的链接
	fmt.Fprintf(w, "<li><a href=\"/\">&larr; 返回首页</a></li>\n")
	
	// 列出所有日志文件
	for _, file := range files {
		if !file.IsDir() && filepath.Ext(file.Name()) == ".txt" {
			fmt.Fprintf(w, "<li><a href=\"/log?file=%s\">%s</a></li>\n", file.Name(), file.Name())
		}
	}
	
	fmt.Fprintf(w, "</ul>\n</body>\n</html>")
}

// serveRaw 提供原始文件内容
func serveRaw(w http.ResponseWriter, r *http.Request, filePath string) {
	// 尝试打开文件
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening file %s: %v", filePath, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	// 获取文件信息
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Error getting file info for %s: %v", filePath, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 检查是否为目录
	if fileInfo.IsDir() {
		http.Error(w, "Directory listing not allowed", http.StatusForbidden)
		return
	}

	// 检查If-Modified-Since头部实现基本缓存
	if modifiedSince := r.Header.Get("If-Modified-Since"); modifiedSince != "" {
		if t, err := time.Parse(time.RFC1123, modifiedSince); err == nil {
			if fileInfo.ModTime().Before(t) || fileInfo.ModTime().Equal(t) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}

	// 获取文件扩展名
	ext := strings.ToLower(filepath.Ext(filePath))
	
	// 定义需要以文本形式显示的文件扩展名
	textExts := map[string]bool{
		".md":   true,
		".list": true,
		".yml":  true,
		".yaml": true,
		".conf": true,
		".txt":  true,
		".lcf":  true,
		".lsr":  true,
		".ini":  true,
		".json": true,
	}
	
	// 如果是文本文件，则以文本形式显示
	if textExts[ext] {
		// 读取文件内容
		content, err := io.ReadAll(file)
		if err != nil {
			log.Printf("Error reading file %s: %v", filePath, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		
		// 设置Content-Type为纯文本
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		
		// 设置Content-Length
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		
		// 写入响应
		w.WriteHeader(http.StatusOK)
		w.Write(content)
		return
	}

	// 对于非文本文件，使用默认的文件服务方式
	// 设置Content-Type
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		// 如果无法根据扩展名确定类型，则设为application/octet-stream
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)

	// 设置Last-Modified用于缓存控制
	w.Header().Set("Last-Modified", fileInfo.ModTime().Format(time.RFC1123))

	// 设置Content-Length
	w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))

	// 将文件内容复制到响应
	_, err = io.Copy(w, file)
	if err != nil {
		log.Printf("Error serving file %s: %v", filePath, err)
		// 注意：此时已经写入了响应头，不能再使用http.Error
		return
	}
}

// tokenCheck 验证token是否有效
func tokenCheck(token string) bool {
	if token == "" {
		return false
	}

	tokenMu.RLock()
	defer tokenMu.RUnlock()

	_, ok := tokens[token]
	return ok
}

// uaCheck 检查User-Agent是否符合规则
func uaCheck(ua string) bool {
	uaRulesMu.RLock()
	defer uaRulesMu.RUnlock()

	// 如果没有规则，默认允许所有UA
	if len(uaRules.Whitelist) == 0 && len(uaRules.Blacklist) == 0 {
		return true
	}

	// 如果在黑名单中，拒绝访问
	for _, pattern := range uaRules.Blacklist {
		if strings.Contains(ua, pattern) {
			return false
		}
	}

	// 如果有白名单但UA不在其中，拒绝访问
	if len(uaRules.Whitelist) > 0 {
		allowed := false
		for _, pattern := range uaRules.Whitelist {
			if strings.Contains(ua, pattern) {
				allowed = true
				break
			}
		}
		return allowed
	}

	// 默认允许
	return true
}

// loadTokens 从环境变量加载token列表
func loadTokens() {
	// 创建新的token映射
	newTokens := make(map[string]bool)

	// 从环境变量读取
	envTokens := os.Getenv("API_TOKENS")
	if envTokens != "" {
		tokenList := strings.Split(envTokens, ",")
		for _, token := range tokenList {
			token = strings.TrimSpace(token)
			if token != "" {
				newTokens[token] = true
			}
		}
		log.Printf("Loaded %d tokens from environment variables", len(newTokens))
	} else {
		log.Println("No tokens loaded from environment variables")
	}

	// 原子替换token映射
	tokenMu.Lock()
	defer tokenMu.Unlock()
	tokens = newTokens
}

// loadUARules 从环境变量加载UA规则
func loadUARules() {
	uaRulesMu.Lock()
	defer uaRulesMu.Unlock()

	// 创建新的UARules结构体
	newRules := UARules{}

	// 从环境变量读取
	if uaWhitelist := os.Getenv("UA_WHITELIST"); uaWhitelist != "" {
		newRules.Whitelist = strings.Split(uaWhitelist, ",")
		// 清理空白字符
		for i, pattern := range newRules.Whitelist {
			newRules.Whitelist[i] = strings.TrimSpace(pattern)
		}
		log.Printf("Loaded UA whitelist from environment: %v", newRules.Whitelist)
	}

	if uaBlacklist := os.Getenv("UA_BLACKLIST"); uaBlacklist != "" {
		newRules.Blacklist = strings.Split(uaBlacklist, ",")
		// 清理空白字符
		for i, pattern := range newRules.Blacklist {
			newRules.Blacklist[i] = strings.TrimSpace(pattern)
		}
		log.Printf("Loaded UA blacklist from environment: %v", newRules.Blacklist)
	}
	
	// 如果没有配置规则，记录日志
	if len(newRules.Whitelist) == 0 && len(newRules.Blacklist) == 0 {
		log.Println("No UA rules loaded from environment variables")
	}

	// 原子替换UA规则
	uaRules = newRules
}