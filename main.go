package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"net/url"
)

type Result struct {
	Name     string `json:"Name"`
	Protocol string `json:"Protocol"`
	Severity string `json:"Severity"`
	URL      string `json:"Url"`
}

// 获取 map 中所有键
func mapKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// 将targets.txt文件分割为多个小文件
func splitTargetFile(targetFile string, batchSize int) ([]string, error) {
	file, err := os.Open(targetFile)
	if err != nil {
		return nil, fmt.Errorf("error opening targets.txt file: %s", err)
	}
	defer file.Close()

	var targetFiles []string
	scanner := bufio.NewScanner(file)
	i := 0
	var batchFile *os.File
	for scanner.Scan() {
		if i%batchSize == 0 {
			if batchFile != nil {
				batchFile.Close()
			}
			batchFileName := fmt.Sprintf("targets_%d.txt", i/batchSize+1)
			targetFiles = append(targetFiles, batchFileName)
			batchFile, err = os.Create(batchFileName)
			if err != nil {
				return nil, fmt.Errorf("error creating target batch file: %s", err)
			}
		}
		_, err := batchFile.WriteString(scanner.Text() + "\n")
		if err != nil {
			return nil, fmt.Errorf("error writing to target batch file: %s", err)
		}
		i++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading targets.txt: %s", err)
	}
	if batchFile != nil {
		batchFile.Close()
	}

	return targetFiles, nil
}

// 将结果追加写入文件
func appendResultsToFile(filename string, newResults map[string][]Result) {
	var results map[string][]Result

	// 读取现有的内容
	fileContent, err := os.ReadFile(filename)
	if err == nil {
		json.Unmarshal(fileContent, &results)
	}

	// 初始化 results 以防止 nil map 的问题
	if results == nil {
		results = make(map[string][]Result)
	}

	// 追加新结果
	for key, newResult := range newResults {
		results[key] = append(results[key], newResult...)
	}

	// 重新写入文件
	file, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening %s file: %s\n", filename, err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(results)
	if err != nil {
		fmt.Printf("Error writing to %s: %s\n", filename, err)
	}
}

// 提取 URL 中的主机和端口部分作为键
func extractHostKey(url string) string {
	// 先去掉可能的方括号及其后面的内容
	url = strings.Split(url, " ")[0]

	// 如果有协议部分，去掉协议
	if strings.Contains(url, "://") {
		url = strings.Split(url, "://")[1]
	}

	// 去掉可能存在的路径部分，只保留主机名和端口
	url = strings.Split(url, "/")[0]

	return url
}

// 提取名称name的逻辑
func extractTemplateNames(resultName string) []string {
	parts := strings.Split(resultName, ":")
	if len(parts) < 2 {
		return nil
	}
	// 使用正则表达式匹配 "-" 和 " "，将其作为分隔符进行拆分
	re := regexp.MustCompile(`[\s-]+`)
	names := re.Split(parts[1], -1)
	return names
}

// 在模板目录中查找匹配的模板文件
func findMatchingTemplates(names []string, templatesDir string) ([]string, error) {
	var templates []string

	err := filepath.WalkDir(templatesDir, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			for _, name := range names {
				if strings.Contains(strings.ToLower(info.Name()), strings.ToLower(name)) {
					templates = append(templates, path)
					break
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking the directory tree: %w", err)
	}

	return templates, nil
}

// 写入模板路径到临时文件
func writeTemplatesToTempFile(templates []string, tempFile *os.File) error {
	for _, tmpl := range templates {
		_, err := tempFile.WriteString(tmpl + "\n")
		if err != nil {
			return fmt.Errorf("error writing to temp file: %w", err)
		}
	}
	return nil
}

// 解析nuclei输出
func parseNucleiOutput(output []byte) map[string][]Result {
	resultMap := make(map[string][]Result)
	lines := string(output)

	re := regexp.MustCompile(`\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)`)
	matches := re.FindAllStringSubmatch(lines, -1)

	for _, match := range matches {
		if len(match) >= 4 {
			result := Result{
				Name:     match[1],
				Protocol: match[2],
				Severity: match[3],
				URL:      match[4],
			}
			hostKey := extractHostKey(result.URL)
			resultMap[hostKey] = append(resultMap[hostKey], result)
		}
	}

	return resultMap
}

// 运行nuclei进行指纹识别
func runFingerprintScan(targetFile string, wg *sync.WaitGroup, sem chan struct{}, fingerprintFile, resultsFile string) {
	defer wg.Done()
	sem <- struct{}{} // 获取信号量
	defer func() { <-sem }() // 释放

	fingerPrintTemplate := "nuclei/finger/ehole_nuclei_finger.yaml,nuclei/finger/etcd_finger.yaml,nuclei/finger/nacos_finger.yaml"
	//fingerPrintTemplate := "nuclei/nuclei_templates/Path/sensitive-api.yaml"
	//fingerPrintTemplate := "Clickjacking.yaml"
	cmd := exec.Command("nuclei/nuclei", "-l", targetFile, "-t", fingerPrintTemplate, "-silent", "-nc")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error executing nuclei for target file %s with fingerprint template: %s\n", targetFile, err)
		return
	}

	resultMap := parseNucleiOutput(output)

	// 分开处理不同模板的结果
	fingerPrintResults := make(map[string][]Result)
	ResultsOthers := make(map[string][]Result)

	for hostKey, results := range resultMap {
		for _, result := range results {
			if strings.Contains(result.Name, "fingerprinthub-web-fingerprints") {
				if result.Name == "fingerprinthub-web-fingerprints:Index_Of" {
					// 如果 result.Name 等于 "fingerprinthub-web-fingerprints:Index_Of"，则直接将其添加到 ResultsOthers
					ResultsOthers[hostKey] = append(ResultsOthers[hostKey], result)
				} else if strings.Contains(result.Name, "fingerprinthub-web-fingerprints:NetData") {
					// 如果 result.Name 包含 "fingerprinthub-web-fingerprints:NetData"，则直接将其添加到 ResultsOthers
					ResultsOthers[hostKey] = append(ResultsOthers[hostKey], result)
				} else if strings.Contains(result.Name, "fingerprinthub-web-fingerprints:Spring Eureka") {
					// 如果 result.Name 包含 "fingerprinthub-web-fingerprints:Spring Eureka"，则直接将其添加到 ResultsOthers
					ResultsOthers[hostKey] = append(ResultsOthers[hostKey], result)
				} else {
					// 如果仅包含 "fingerprinthub-web-fingerprints"，但不等于其他特定条件，则添加到 fingerPrintResults
					fingerPrintResults[hostKey] = append(fingerPrintResults[hostKey], result)
				}
			} else {
				// 其他情况直接添加到 ResultsOthers
				ResultsOthers[hostKey] = append(ResultsOthers[hostKey], result)
			}
		}
	}

	// 将fingerprinthub-web-fingerprints的结果写入finger.json
	appendResultsToFile(fingerprintFile, fingerPrintResults)

	// 将sensitive-api的结果写入results.json
	appendResultsToFile(resultsFile, ResultsOthers)

	// 删除已处理的target文件
	err = os.Remove(targetFile)
	if err != nil {
		fmt.Printf("Error deleting target file %s: %s\n", targetFile, err)
	}
}

// 模板匹配函数
func matchTemplates(target string, results []Result, templatesDir string) (string, error) {
	tempTemplateFile, err := os.CreateTemp(".", "templates_*.txt")
	if err != nil {
		return "", fmt.Errorf("error creating temp template file for target %s: %s", target, err)
	}
	defer tempTemplateFile.Close()

	names := map[string]bool{}
	for _, result := range results {
		// 这里的 extractTemplateNames 返回一个字符串切片
		for _, part := range extractTemplateNames(result.Name) {
			names[part] = true
		}
	}

	templates, err := findMatchingTemplates(mapKeys(names), templatesDir)
	if err != nil {
		return "", fmt.Errorf("error finding templates for target %s: %s", target, err)
	}

	if len(templates) == 0 {
		// 如果没有匹配的模板，则关闭并删除临时文件
		os.Remove(tempTemplateFile.Name())
		return "", nil
	}

	err = writeTemplatesToTempFile(templates, tempTemplateFile)
	if err != nil {
		os.Remove(tempTemplateFile.Name())
		return "", fmt.Errorf("error writing templates to temp file for target %s: %s", target, err)
	}

	return tempTemplateFile.Name(), nil
}

// 模板扫描函数
func scanWithTemplates(target string, templateFile string, wg *sync.WaitGroup, sem chan struct{}, resultsFile string) {
	defer wg.Done()
	sem <- struct{}{}
	defer func() { <-sem }()

	cmd := exec.Command("nuclei/nuclei", "-u", target, "-t", templateFile, "-silent", "-nc")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error executing nuclei for target %s with template %s: %s\n", target, templateFile, err)
		return
	}

	resultMap := parseNucleiOutput(output)

	appendResultsToFile(resultsFile, resultMap)

	// 删除临时模板文件
	err = os.Remove(templateFile)
	if err != nil {
		fmt.Printf("Error deleting temp template file %s: %s\n", templateFile, err)
	}
}

func main() {
	const batchSize = 500
	const numWorkers = 20
	const templatesDir = "nuclei/nuclei_templates/POC"

	targetFile := "targets.txt"
	fingerprintFile := "finger.json"
	resultsFile := "results.json"

	targetFiles, err := splitTargetFile(targetFile, batchSize)
	if err != nil {
		fmt.Printf("Error splitting targets file: %s\n", err)
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, numWorkers)

	// 执行指纹识别扫描
	for _, tFile := range targetFiles {
		wg.Add(1)
		go runFingerprintScan(tFile, &wg, sem, fingerprintFile, resultsFile)
	}

	wg.Wait()

	// 处理指纹识别结果并进行模板匹配和扫描
	fingerResultsFile, err := os.Open(fingerprintFile)
	if err != nil {
		fmt.Printf("Error opening fingerprint results file: %s\n", err)
		return
	}
	defer fingerResultsFile.Close()

	var allResults map[string][]Result
	decoder := json.NewDecoder(fingerResultsFile)
	if err := decoder.Decode(&allResults); err != nil {
		fmt.Printf("Error decoding fingerprint results: %s\n", err)
		return
	}

	for _, results := range allResults {
		for _, result := range results {
			// 假设 result.URL 是你想要提取的 URL
			parsedURL, err := url.Parse(result.URL)
			if err != nil {
				fmt.Printf("Error parsing URL %s: %s\n", result.URL, err)
				continue
			}
			
			// 只保留主机部分
			target := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	
			tempFile, err := matchTemplates(target, results, templatesDir)
			if err != nil {
				fmt.Printf("Error matching templates for target %s: %s\n", target, err)
				continue
			}
			if tempFile == "" {
				continue
			}
	
			wg.Add(1)
			go scanWithTemplates(target, tempFile, &wg, sem, resultsFile)
		}
	}

	wg.Wait()
	fmt.Println("Scanning completed and results written to results.json")
}