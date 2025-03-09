package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tebeka/selenium"
)

// Constante usada para o modo "finder" (parâmetros hardcoded)
const finderQuery = "?total=total&log=log&pwd=pwd&redirect_to=redirect_to&embedded_submission_form_uuid=embedded_submission_form_uuid&limit=limit&sort=sort&type=type&sig=sig&version=version&slug=slug&user_id=user_id&countID=countID&perPage=perPage&city_id=city_id&a=a&b=b&c=c&d=d&e=e&f=f&g=g&h=h&i=i&j=j&k=k&l=l&m=m&n=n&o=o&p=p&t=t&v=v&w=w&x=x&y=y&z=z&region=region&country=country&last_id=last_id&_id=_id&cat=cat&item=item&readPdf=readPdf&file=file&uri=uri&token=token&r=r&redir=redir&redirect=redirect&destino=destino&origem=origem&src=src&source=source&destination=destination&dst=dst&dest=dest&index=index&imei=imei&msisdn=msisdn&phone=phone&number=number&num=num&numero=numero&targetEmail=targetEmail&target=target&img=img&image=image&message=message&pageID=pageID&page=page&campaign=campaign&campaignID=campaignID&status=status&report=report&mail=mail&email=email&list=list&select[list]=select[list]&select=select&otp=otp&ProductID=ProductID&id=id&username=username&password=password&uname=uname&pass=pass&username=username&location=location&url=url&u=u&p=p&name=name&search=search&product=product&filter=filter&query=query&q=q&searchForm=searchForm&test=test&goButton=goButton&text=text&tfUname=tfUPass&tfUPass=tfUPass&data=data&user=user&pass=pass&post=post&pid=pid&u=u&s=s&path=path&PHPSESSID=PHPSESSID&lang=lang&language=language&note=note"

// getFreePort retorna uma porta TCP livre no localhost.
func getFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	addr := l.Addr().(*net.TCPAddr)
	return addr.Port, nil
}

func verifyExtension(u string) string {
	re := regexp.MustCompile(`\.[a-zA-Z]{1,5}$`)
	return re.FindString(u)
}

// fullyEncodeURL faz o parsing da URL e re-encoda a query, garantindo que o output esteja totalmente percent-encoded.
func fullyEncodeURL(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	parsed.RawQuery = parsed.Query().Encode()
	return parsed.String()
}

func buildQueryString(params map[string]string) string {
	values := url.Values{}
	for k, v := range params {
		values.Set(k, v)
	}
	return values.Encode()
}

// getInjectionLabel retorna o rótulo do modo de injeção para o output.
func getInjectionLabel(injectionType string) string {
	switch injectionType {
	case "finder":
		return "(finder)"
	case "clusterbomb":
		return "(clusterbomb)"
	default:
		return "(single)"
	}
}

// chunkSlice agrupa uma fatia de strings em chunks do tamanho especificado.
func chunkSlice(slice []string, chunkSize int) [][]string {
	var chunks [][]string
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	return chunks
}

// parseFinderParams extrai os nomes dos parâmetros da finderQuery.
func parseFinderParams() []string {
	q, err := url.ParseQuery(strings.TrimPrefix(finderQuery, "?"))
	if err != nil {
		return []string{}
	}
	var params []string
	for k := range q {
		params = append(params, k)
	}
	sort.Strings(params)
	return params
}

// injectPayload injeta os payloads conforme o modo de injeção e chama as funções de confirmação.
func injectPayload(originalURL string, payloads []string, injectionType, attack, mode string, verbose bool) {
	parts := strings.SplitN(originalURL, "?", 2)
	baseURL := parts[0]
	params := make(map[string]string)
	if len(parts) > 1 {
		pairs := strings.Split(parts[1], "&")
		for _, pair := range pairs {
			if strings.Contains(pair, "=") {
				kv := strings.SplitN(pair, "=", 2)
				params[kv[0]] = kv[1]
			} else {
				params[pair] = ""
			}
		}
	}

	switch injectionType {
	case "uri":
		for _, payload := range payloads {
			if verifyExtension(originalURL) == "" {
				rootURL := baseURL + "/" + payload
				if mode == "xss" {
					if verbose {
						fmt.Printf("%s URL: %s\n", getInjectionLabel(injectionType), fullyEncodeURL(rootURL))
					}
					confirmXSS(rootURL, "", injectionType, "")
				} else if mode == "sqli" {
					confirmSQLi(rootURL, verbose)
				}
			}
		}
	case "finder":
		// Se não houver parâmetros, forçamos o uso dos parâmetros hardcoded.
		if len(params) == 0 {
			parts := strings.SplitN(originalURL, "?", 2)
			originalURL = parts[0] + finderQuery
			pairs := strings.Split(strings.TrimPrefix(finderQuery, "?"), "&")
			for _, pair := range pairs {
				if strings.Contains(pair, "=") {
					kv := strings.SplitN(pair, "=", 2)
					params[kv[0]] = kv[1]
				} else {
					params[pair] = ""
				}
			}
		}
		// Para cada payload, injeta em todos os parâmetros de uma só vez.
		for _, payload := range payloads {
			paramsCopy := make(map[string]string)
			for k, v := range params {
				if attack == "replace" {
					paramsCopy[k] = payload
				} else {
					paramsCopy[k] = v + payload
				}
			}
			fullURL := baseURL + "?" + buildQueryString(paramsCopy)
			if mode == "xss" {
				if verbose {
					fmt.Printf("%s URL: %s | Payload: %s\n", getInjectionLabel(injectionType), fullyEncodeURL(baseURL), payload)
				}
				confirmXSS(fullURL, payload, injectionType, "")
			} else if mode == "sqli" {
				confirmSQLi(fullURL, verbose)
			}
		}
	case "param":
		// Para cada parâmetro, injeta cada payload.
		for param := range params {
			for _, payload := range payloads {
				paramsCopy := make(map[string]string)
				for k, v := range params {
					paramsCopy[k] = v
				}
				if attack == "replace" {
					paramsCopy[param] = payload
				} else {
					paramsCopy[param] = paramsCopy[param] + payload
				}
				fullURL := baseURL + "?" + buildQueryString(paramsCopy)
				if mode == "xss" {
					if verbose {
						fmt.Printf("%s URL: %s\n", getInjectionLabel(injectionType), fullyEncodeURL(fullURL))
					}
					confirmXSS(fullURL, payload, injectionType, param)
				} else if mode == "sqli" {
					confirmSQLi(fullURL, verbose)
				}
			}
		}
	case "clusterbomb":
		// Injeção em cluster: injeta o payload em todos os parâmetros simultaneamente.
		for _, payload := range payloads {
			paramsCopy := make(map[string]string)
			for k, v := range params {
				paramsCopy[k] = v
			}
			for param := range params {
				if attack == "replace" {
					paramsCopy[param] = payload
				} else {
					paramsCopy[param] = paramsCopy[param] + payload
				}
			}
			fullURL := baseURL + "?" + buildQueryString(paramsCopy)
			if mode == "xss" {
				if verbose {
					fmt.Printf("%s URL: %s\n", getInjectionLabel(injectionType), fullyEncodeURL(fullURL))
				}
				confirmXSS(fullURL, payload, injectionType, "")
			} else if mode == "sqli" {
				confirmSQLi(fullURL, verbose)
			}
		}
	}
}

// confirmXSS utiliza o Selenium para carregar a URL e verifica se há alerta.
// Se injectedParam não for vazio, exibe também o payload e, se não for finder, o parâmetro.
func confirmXSS(urlStr, payload, injectionType, injectedParam string) {
	port, err := getFreePort()
	if err != nil {
		log.Printf("Erro ao obter porta livre: %v", err)
		return
	}
	const seleniumPath = "chromedriver"
	opts := []selenium.ServiceOption{}
	service, err := selenium.NewChromeDriverService(seleniumPath, port, opts...)
	if err != nil {
		log.Printf("Erro ao iniciar o ChromeDriver: %v", err)
		return
	}
	defer service.Stop()
	caps := selenium.Capabilities{"browserName": "chrome"}
	chromeCaps := []string{
		"--headless",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--ignore-certificate-errors",
	}
	caps["goog:chromeOptions"] = map[string]interface{}{"args": chromeCaps}
	wd, err := selenium.NewRemote(caps, fmt.Sprintf("http://localhost:%d/wd/hub", port))
	if err != nil {
		log.Printf("Erro ao conectar com o WebDriver: %v", err)
		return
	}
	defer wd.Quit()
	if err = wd.Get(urlStr); err != nil {
		log.Printf("Erro ao carregar a URL: %v", err)
		return
	}
	time.Sleep(2 * time.Second)
	if _, err := wd.AlertText(); err == nil {
		encoded := fullyEncodeURL(urlStr)
		// Se injectedParam não estiver vazio e não for finder, exibe o parâmetro.
		if injectedParam != "" && injectionType != "finder" {
			fmt.Printf("\033[92m%s Vulnerable URL: \033[32m%s\033[0m | Param: \033[33m%s\033[0m | Payload: \033[31m%s\033[0m\n",
				getInjectionLabel(injectionType), encoded, injectedParam, payload)
		} else {
			fmt.Printf("\033[92m%s Vulnerable URL: \033[32m%s\033[0m | Payload: \033[31m%s\033[0m\n",
				getInjectionLabel(injectionType), encoded, payload)
		}
		if err := wd.AcceptAlert(); err != nil {
			log.Printf("Erro ao aceitar o alerta: %v", err)
		}
	}
}

// confirmSQLi realiza requisições GET e POST para detectar SQLi baseado em tempo.
func confirmSQLi(urlStr string, verbose bool) {
	client := &http.Client{
		Timeout: 30 * time.Second, // Timeout aumentado para 60 segundos
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	start := time.Now()
	resp, err := client.Get(urlStr)
	if err != nil {
		// Se o erro for de timeout, consideramos vulnerável
		if strings.Contains(err.Error(), "context deadline exceeded") {
			fmt.Printf("\033[91m\nTime Based SQLi Found (Timeout)!\033[0m\n")
			fmt.Printf("\033[92mURL: \033[32m%s\033[0m\n", fullyEncodeURL(urlStr))
			return
		}
		log.Printf("Erro na requisição GET: %v", err)
		return
	}
	elapsed := time.Since(start).Seconds()

	if elapsed > 21 && elapsed < 25 {
		start2 := time.Now()
		_, err2 := client.Post(urlStr, "application/x-www-form-urlencoded", nil)
		if err2 != nil {
			// Se der timeout na POST, consideramos vulnerável também
			if strings.Contains(err2.Error(), "context deadline exceeded") {
				fmt.Printf("\033[91m\nTime Based SQLi Found (Timeout POST)!\033[0m\n")
				fmt.Printf("\033[92mURL: \033[32m%s\033[0m\n", fullyEncodeURL(urlStr))
				return
			}
			log.Printf("Erro na requisição POST: %v", err2)
			return
		}
		elapsed2 := time.Since(start2).Seconds()
		if elapsed2 > 21 && elapsed2 < 25 {
			fmt.Printf("\033[91m\nTime Based SQLi Found!\033[0m\n")
			fmt.Printf("\033[92mStatus: %d | URL: \033[32m%s\033[0m | Response Time: \033[31m%.2fs\033[0m\n",
				resp.StatusCode, fullyEncodeURL(resp.Request.URL.String()), elapsed2)
		}
	} else if verbose {
		fmt.Printf("\nStatus: %d | URL: %s | Response Time: %.2fs\n",
			resp.StatusCode, fullyEncodeURL(resp.Request.URL.String()), elapsed)
	}
}

// testURL processa a injeção utilizando os payloads e respeita o número de threads.
func testURL(urlStr string, payloads []string, injectionType, attack, mode string, verbose bool, threads int) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	for _, payload := range payloads {
		wg.Add(1)
		sem <- struct{}{}
		go func(pl string) {
			defer wg.Done()
			injectPayload(urlStr, []string{pl}, injectionType, attack, mode, verbose)
			<-sem
		}(payload)
	}
	wg.Wait()
}

// newCustomTestURL injeta todos os parâmetros customizados simultaneamente (clusterbomb).
func newCustomTestURL(urlStr string, params []string, payload, mode string, verbose bool) {
	sep := "?"
	if strings.Contains(urlStr, "?") {
		sep = "&"
	}
	var injections []string
	for _, p := range params {
		injections = append(injections, fmt.Sprintf("%s=%s", p, payload))
	}
	newURL := urlStr + sep + strings.Join(injections, "&")
	if verbose {
		fmt.Printf("Custom URL (clusterbomb): %s\n", fullyEncodeURL(newURL))
	}
	if mode == "xss" {
		confirmXSS(newURL, payload, "custom", strings.Join(params, ","))
	} else if mode == "sqli" {
		confirmSQLi(newURL, verbose)
	} else {
		fmt.Printf("Modo inválido: %s\n", mode)
	}
}

// singleCustomTestURL injeta um único parâmetro customizado com o payload.
func singleCustomTestURL(urlStr, param, payload, mode string, verbose bool) {
	sep := "?"
	if strings.Contains(urlStr, "?") {
		sep = "&"
	}
	newURL := urlStr + sep + param + "=" + payload
	if verbose {
		fmt.Printf("Custom URL (single): %s\n", fullyEncodeURL(newURL))
	}
	if mode == "xss" {
		confirmXSS(newURL, payload, "custom", param)
	} else if mode == "sqli" {
		confirmSQLi(newURL, verbose)
	} else {
		fmt.Printf("Modo inválido: %s\n", mode)
	}
}

// processCustomPayloadURLs injeta os payloads customizados nos parâmetros especificados.
// Se não estiver no modo "clusterbomb", agrupa os parâmetros em chunks conforme a flag -cs (chunk size).
// No modo finder, os parâmetros são obtidos da finderQuery.
func processCustomPayloadURLs(urls []string, paramStr string, payloads []string, mode string, injectionType string, verbose bool, threads int, chunkSize int) {
	var paramList []string
	if injectionType == "finder" {
		paramList = parseFinderParams()
	} else {
		paramList = strings.Split(paramStr, ",")
		for i, p := range paramList {
			paramList[i] = strings.TrimSpace(p)
		}
	}
	var chunks [][]string
	if chunkSize > 0 && len(paramList) > chunkSize {
		chunks = chunkSlice(paramList, chunkSize)
	} else {
		chunks = [][]string{paramList}
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)
	for _, urlStr := range urls {
		u := urlStr
		if injectionType == "finder" {
			parts := strings.SplitN(u, "?", 2)
			u = parts[0] + finderQuery
		}
		for _, payload := range payloads {
			for _, chunk := range chunks {
				wg.Add(1)
				sem <- struct{}{}
				go func(u string, paramsChunk []string, p string) {
					defer wg.Done()
					// No modo finder, injetamos todos os parâmetros de uma vez.
					if injectionType == "finder" {
						newCustomTestURL(u, paramsChunk, p, mode, verbose)
					} else {
						// Nos demais modos, injetamos o grupo de parâmetros como uma única string.
						singleCustomTestURL(u, strings.Join(paramsChunk, ","), p, mode, verbose)
					}
					<-sem
				}(u, chunk, payload)
			}
		}
	}
	wg.Wait()
}

func singleURL(urlStr, wordlist, injectionType, attack, mode string, verbose bool, threads int) {
	data, err := ioutil.ReadFile(wordlist)
	if err != nil {
		log.Fatalf("Erro ao ler wordlist: %v", err)
	}
	payloads := strings.Split(string(data), "\n")
	if injectionType == "finder" {
		parts := strings.SplitN(urlStr, "?", 2)
		urlStr = parts[0] + finderQuery
	}
	testURL(urlStr, payloads, injectionType, attack, mode, verbose, threads)
}

func processURLs(filePath, wordlist, injectionType, attack, mode string, verbose bool, threads int) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("Erro ao abrir o arquivo de URLs: %v", err)
	}
	defer file.Close()
	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			if injectionType == "finder" {
				parts := strings.SplitN(line, "?", 2)
				line = parts[0] + finderQuery
			}
			urls = append(urls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Erro ao ler o arquivo: %v", err)
	}
	data, err := ioutil.ReadFile(wordlist)
	if err != nil {
		log.Fatalf("Erro ao ler wordlist: %v", err)
	}
	payloads := strings.Split(string(data), "\n")
	var wg sync.WaitGroup
	for _, urlStr := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			testURL(u, payloads, injectionType, attack, mode, verbose, threads)
		}(urlStr)
	}
	wg.Wait()
}

func main() {
	urlFlag := flag.String("u", "", "URL única para teste (XSS ou SQLi)")
	urlsFile := flag.String("l", "", "Caminho para arquivo com lista de URLs")
	wordlist := flag.String("w", "", "Caminho para o arquivo com payloads")
	attack := flag.String("a", "postfix", "Tipo de ataque: 'postfix' ou 'replace'")
	injectionType := flag.String("it", "param", "Modo de injeção: 'uri', 'param', 'cookie', 'referer', 'finder', 'clusterbomb'")
	mode := flag.String("m", "xss", "Modo de injeção: 'xss' ou 'sqli'")
	threads := flag.Int("t", 10, "Número de threads")
	chunkSize := flag.Int("cs", 20, "Número de parâmetros a serem injetados por request (chunk size)")
	verbose := flag.Bool("v", false, "Habilita logs detalhados")
	// Flags customizadas
	customParam := flag.String("param", "", "Parâmetro(s) customizado(s) para injeção (separados por vírgula)")
	customPayload := flag.String("payload", "", "Payload customizado para injeção")
	flag.Parse()

	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetOutput(ioutil.Discard)
	}

	// Se -payload for fornecido sem -param, o payload será injetado nos parâmetros já existentes da URL.
	if *customPayload != "" && *customParam == "" {
		payloadList := []string{*customPayload}
		if *urlFlag != "" {
			testURL(*urlFlag, payloadList, *injectionType, *attack, *mode, *verbose, *threads)
			return
		}
		if *urlsFile != "" {
			file, err := os.Open(*urlsFile)
			if err != nil {
				log.Fatalf("Erro ao abrir o arquivo de URLs: %v", err)
			}
			defer file.Close()
			var urls []string
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					urls = append(urls, line)
				}
			}
			if err := scanner.Err(); err != nil {
				log.Fatalf("Erro ao ler o arquivo: %v", err)
			}
			var wg sync.WaitGroup
			for _, u := range urls {
				wg.Add(1)
				go func(urlStr string) {
					defer wg.Done()
					testURL(urlStr, payloadList, *injectionType, *attack, *mode, *verbose, *threads)
				}(u)
			}
			wg.Wait()
			return
		}
		var urls []string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				urls = append(urls, line)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Erro ao ler da entrada padrão: %v", err)
		}
		var wg sync.WaitGroup
		for _, u := range urls {
			wg.Add(1)
			go func(urlStr string) {
				defer wg.Done()
				testURL(urlStr, payloadList, *injectionType, *attack, *mode, *verbose, *threads)
			}(u)
		}
		wg.Wait()
		return
	}

	// Se o usuário informar parâmetros customizados (-param), entra no modo custom.
	if *customParam != "" {
		var payloadList []string
		if *wordlist != "" {
			data, err := ioutil.ReadFile(*wordlist)
			if err != nil {
				log.Fatalf("Erro ao ler wordlist: %v", err)
			}
			payloadList = strings.Split(string(data), "\n")
		} else if *customPayload != "" {
			payloadList = []string{*customPayload}
		} else {
			log.Fatal("Você precisa fornecer -payload ou -w junto com -param")
		}

		if *urlFlag != "" {
			processCustomPayloadURLs([]string{*urlFlag}, *customParam, payloadList, *mode, *injectionType, *verbose, *threads, *chunkSize)
			return
		}
		if *urlsFile != "" {
			file, err := os.Open(*urlsFile)
			if err != nil {
				log.Fatalf("Erro ao abrir o arquivo de URLs: %v", err)
			}
			defer file.Close()
			var urls []string
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					urls = append(urls, line)
				}
			}
			if err := scanner.Err(); err != nil {
				log.Fatalf("Erro ao ler o arquivo: %v", err)
			}
			processCustomPayloadURLs(urls, *customParam, payloadList, *mode, *injectionType, *verbose, *threads, *chunkSize)
			return
		}
		var urls []string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				urls = append(urls, line)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Erro ao ler da entrada padrão: %v", err)
		}
		if len(urls) > 0 {
			processCustomPayloadURLs(urls, *customParam, payloadList, *mode, *injectionType, *verbose, *threads, *chunkSize)
			return
		}
	}

	// Se não estiver em modo custom, utiliza os métodos tradicionais.
	if *urlFlag != "" {
		singleURL(*urlFlag, *wordlist, *injectionType, *attack, *mode, *verbose, *threads)
		return
	}
	if *urlsFile != "" {
		processURLs(*urlsFile, *wordlist, *injectionType, *attack, *mode, *verbose, *threads)
		return
	}
	var urls []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			if *injectionType == "finder" {
				parts := strings.SplitN(line, "?", 2)
				line = parts[0] + finderQuery
			}
			urls = append(urls, line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Erro ao ler da entrada padrão: %v", err)
	}
	if len(urls) > 0 {
		data, err := ioutil.ReadFile(*wordlist)
		if err != nil {
			log.Fatalf("Erro ao ler wordlist: %v", err)
		}
		payloads := strings.Split(string(data), "\n")
		var wg sync.WaitGroup
		for _, urlStr := range urls {
			wg.Add(1)
			go func(u string) {
				defer wg.Done()
				testURL(u, payloads, *injectionType, *attack, *mode, *verbose, *threads)
			}(urlStr)
		}
		wg.Wait()
	}
}
