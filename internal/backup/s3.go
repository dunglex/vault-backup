package backup

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type S3Config struct {
	Enabled         bool
	Endpoint        string
	Region          string
	Bucket          string
	Prefix          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	ForcePathStyle  bool
}

func ValidateS3Config(config S3Config) error {
	return config.validate()
}

func (c S3Config) validate() error {
	if strings.TrimSpace(c.Region) == "" {
		return fmt.Errorf("S3 region is required")
	}
	if strings.TrimSpace(c.Bucket) == "" {
		return fmt.Errorf("S3 bucket is required")
	}
	if strings.TrimSpace(c.AccessKeyID) == "" || strings.TrimSpace(c.SecretAccessKey) == "" {
		return fmt.Errorf("S3 access key ID and secret access key are required")
	}
	if c.Endpoint != "" {
		parsed, err := url.Parse(c.Endpoint)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("S3 endpoint must be an HTTP or HTTPS URL")
		}
		if strings.ContainsAny(c.Endpoint, "\r\n") {
			return fmt.Errorf("S3 endpoint is invalid")
		}
	}
	return nil
}

func TestS3Connection(config S3Config) error {
	if err := config.validate(); err != nil {
		return err
	}
	req, err := newSignedS3Request(http.MethodHead, config, "", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("S3 connection failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = response.Status
		}
		return fmt.Errorf("S3 connection failed: %s", message)
	}
	return nil
}

func CopyToS3(config S3Config, archivePath string) (string, error) {
	if err := config.validate(); err != nil {
		return "", err
	}
	file, err := os.Open(archivePath)
	if err != nil {
		return "", fmt.Errorf("open backup archive for S3 upload: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect backup archive for S3 upload: %w", err)
	}

	name := path.Base(filepathSlash(archivePath))
	key := strings.Trim(strings.TrimSpace(config.Prefix), "/")
	if key != "" {
		key += "/" + name
	} else {
		key = name
	}
	req, err := newSignedS3Request(http.MethodPut, config, key, file)
	if err != nil {
		return "", err
	}
	req.ContentLength = info.Size()
	req.Header.Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	req.Header.Set("Content-Type", "application/gzip")
	client := &http.Client{Timeout: 30 * time.Minute}
	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload backup to S3 failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = response.Status
		}
		return "", fmt.Errorf("upload backup to S3 failed: %s", message)
	}
	return key, nil
}

func filepathSlash(value string) string {
	return strings.ReplaceAll(value, "\\", "/")
}

func newSignedS3Request(method string, config S3Config, key string, body io.Reader) (*http.Request, error) {
	endpoint := strings.TrimRight(strings.TrimSpace(config.Endpoint), "/")
	if endpoint == "" {
		endpoint = "https://s3." + strings.TrimSpace(config.Region) + ".amazonaws.com"
	}
	base, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse S3 endpoint: %w", err)
	}
	host := base.Host
	requestPath := ""
	if config.ForcePathStyle {
		if basePath := strings.Trim(base.EscapedPath(), "/"); basePath != "" {
			requestPath = "/" + escapeS3Path(basePath)
		}
		if config.Bucket != "" {
			requestPath += "/" + escapeS3Path(config.Bucket)
		}
	} else if strings.TrimSpace(config.Bucket) != "" {
		host = config.Bucket + "." + base.Host
	}
	requestPath = strings.TrimRight(requestPath, "/")
	if key != "" {
		if requestPath == "" {
			requestPath = "/" + escapeS3Path(key)
		} else {
			requestPath += "/" + escapeS3Path(key)
		}
	}
	if requestPath == "" {
		requestPath = "/"
	}
	target := base.Scheme + "://" + host + requestPath
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return nil, fmt.Errorf("create S3 request: %w", err)
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHash := sha256Hex(body)
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("Host", host)
	if config.SessionToken != "" {
		req.Header.Set("x-amz-security-token", config.SessionToken)
	}
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"
	if config.SessionToken != "" {
		signedHeaders = "host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
	}
	canonicalHeaders := "host:" + host + "\n" +
		"x-amz-content-sha256:" + payloadHash + "\n" +
		"x-amz-date:" + amzDate + "\n"
	if config.SessionToken != "" {
		canonicalHeaders += "x-amz-security-token:" + config.SessionToken + "\n"
	}
	canonicalURI := requestPath
	canonicalQuery := ""
	canonicalRequest := method + "\n" + canonicalURI + "\n" + canonicalQuery + "\n" +
		canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash
	canonicalRequestHash := fmt.Sprintf("%x", sha256.Sum256([]byte(canonicalRequest)))
	scope := dateStamp + "/" + config.Region + "/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + canonicalRequestHash
	signingKey := hmacSHA256(hmacSHA256(hmacSHA256(hmacSHA256([]byte("AWS4"+config.SecretAccessKey), dateStamp), config.Region), "s3"), "aws4_request")
	signature := fmt.Sprintf("%x", hmacSHA256(signingKey, stringToSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+config.AccessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
	return req, nil
}

func sha256Hex(body io.Reader) string {
	if body == nil {
		return fmt.Sprintf("%x", sha256.Sum256(nil))
	}
	if seeker, ok := body.(io.ReadSeeker); ok {
		current, err := seeker.Seek(0, io.SeekCurrent)
		if err == nil {
			hash := sha256.New()
			_, _ = io.Copy(hash, seeker)
			_, _ = seeker.Seek(current, io.SeekStart)
			return fmt.Sprintf("%x", hash.Sum(nil))
		}
	}
	return fmt.Sprintf("%x", sha256.Sum256(nil))
}

func hmacSHA256(key []byte, value string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func escapeS3Path(value string) string {
	segments := strings.Split(strings.Trim(value, "/"), "/")
	escaped := make([]string, 0, len(segments))
	for _, segment := range segments {
		escaped = append(escaped, url.PathEscape(segment))
	}
	return strings.Join(escaped, "/")
}
