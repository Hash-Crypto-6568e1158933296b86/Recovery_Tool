package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

const (
	progressFile    = "progresso.json"
	batchSize       = 1000
	maxQueueSize    = 100000
	progressSaveSec = 30
)

var (
	login = `
                                               
                  ____ ___ _____ ____ ___ ___ _   _ 
                 | __ )_ _|_   _/ ___/ _ \_ _| \ | |
                 |  _ \| |  | || |  | | | | ||  \| |
                 | |_) | |  | || |__| |_| | || |\  |
                 |____/___| |_| \____\___/___|_| \_|
                                    

                BIP39 Recovery Tool - BIP44 CUSTOM INDEX
`
	bip39WordList []string
	wordToIndex   map[string]int
	netParams     = &chaincfg.MainNetParams

	// checksumBitsForWordCount mapeia o número de palavras BIP39 para o número
	// de bits de checksum (definido pela spec: ENT+CS = 11*n, CS = ENT/32).
	checksumBitsForWordCount = map[int]int{
		12: 4,
		15: 5,
		18: 6,
		21: 7,
		24: 8,
	}
	languageFiles = map[string]string{
		"a": "english.txt",
		"b": "portuguese.txt",
		"c": "japanese.txt",
		"d": "korean.txt",
		"e": "spanish.txt",
		"f": "chinese_simplified.txt",
		"g": "chinese_traditional.txt",
		"h": "french.txt",
		"i": "italian.txt",
		"j": "czech.txt",
	}
	currentLanguage string
)

type Progress struct {
	BaseWords       []string `json:"palavras_base"`
	CurrentIndex    int64    `json:"indice_atual"`
	TotalPerms      int64    `json:"total_permutacoes"`
	KeysTested      int64    `json:"chaves_testadas"`
	Timestamp       int64    `json:"timestamp"`
	Strategy        string   `json:"estrategia"`
	PriorityWords   []string `json:"palavras_prioritarias"`
	DerivationPath  string   `json:"caminho_derivacao"`
	CurrentMnemonic string   `json:"mnemonic_atual"`
	AddressIndex    uint32   `json:"indice_endereco"`
	WordCount       int      `json:"contagem_palavras"`
}

type SmartScheduler struct {
	sync.RWMutex
	highPriorityWords  []string
	wordFrequency      map[string]int
	performanceMetrics map[string]float64
}

func NewSmartScheduler() *SmartScheduler {
	return &SmartScheduler{
		highPriorityWords:  make([]string, 0),
		wordFrequency:      make(map[string]int),
		performanceMetrics: make(map[string]float64),
	}
}

func (ss *SmartScheduler) AddWordFrequency(words []string) {
	ss.Lock()
	defer ss.Unlock()

	for _, word := range words {
		ss.wordFrequency[word]++
	}

	type wordFreq struct {
		word  string
		count int
	}
	var freqList []wordFreq
	for word, count := range ss.wordFrequency {
		freqList = append(freqList, wordFreq{word, count})
	}

	sort.Slice(freqList, func(i, j int) bool {
		return freqList[i].count > freqList[j].count
	})

	ss.highPriorityWords = make([]string, 0)
	for i := 0; i < len(freqList) && i < 5; i++ {
		ss.highPriorityWords = append(ss.highPriorityWords, freqList[i].word)
	}
}

func (ss *SmartScheduler) GetPriorityWords() []string {
	ss.RLock()
	defer ss.RUnlock()
	return ss.highPriorityWords
}

var (
	smartScheduler = NewSmartScheduler()
)

func init() {
	selectLanguage()
	loadBIP39Dictionary()
	sort.Strings(bip39WordList)

	wordToIndex = make(map[string]int, len(bip39WordList))
	for i, w := range bip39WordList {
		wordToIndex[w] = i
	}
}

func selectLanguage() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n🌍 SELECIONE O IDIOMA DO DICIONÁRIO BIP39:")
	fmt.Println("a - English")
	fmt.Println("b - Portuguese")
	fmt.Println("c - Japanese")
	fmt.Println("d - Korean")
	fmt.Println("e - Spanish")
	fmt.Println("f - Chinese (Simplified)")
	fmt.Println("g - Chinese (Traditional)")
	fmt.Println("h - French")
	fmt.Println("i - Italian")
	fmt.Println("j - Czech")

	for {
		fmt.Print("\n👉 Digite a letra do idioma desejado: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		if filename, exists := languageFiles[choice]; exists {
			// Verificar se o arquivo existe na pasta wordlist
			filepath := "wordlist/" + filename
			if _, err := os.Stat(filepath); err == nil {
				currentLanguage = choice
				fmt.Printf("✅ Idioma selecionado: %s\n", getLanguageName(choice))
				return
			} else {
				fmt.Printf("❌ Arquivo de dicionário não encontrado: %s\n", filepath)
				fmt.Printf("💡 Certifique-se de que a pasta 'wordlist' existe e contém os arquivos de dicionário.\n")
			}
		} else {
			fmt.Println("❌ Opção inválida. Por favor, escolha uma letra de a a j.")
		}
	}
}

func getLanguageName(choice string) string {
	names := map[string]string{
		"a": "English",
		"b": "Portuguese",
		"c": "Japanese",
		"d": "Korean",
		"e": "Spanish",
		"f": "Chinese (Simplified)",
		"g": "Chinese (Traditional)",
		"h": "French",
		"i": "Italian",
		"j": "Czech",
	}
	return names[choice]
}

func loadBIP39Dictionary() {
	// Usar o idioma selecionado ou fallback para english
	filename := "english.txt"
	if currentLanguage != "" {
		if langFile, exists := languageFiles[currentLanguage]; exists {
			filename = langFile
		}
	}

	filepath := "wordlist/" + filename
	file, err := os.Open(filepath)
	if err != nil {
		// Tentar fallback para arquivo no diretório atual
		file, err = os.Open(filename)
		if err != nil {
			log.Fatalf("Erro ao abrir arquivo de dicionário '%s': %v", filepath, err)
		}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	bip39WordList = make([]string, 0)

	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			bip39WordList = append(bip39WordList, word)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("Erro ao ler arquivo de dicionário: %v", err)
	}

	if len(bip39WordList) != 2048 {
		log.Fatalf("Tamanho inválido da lista de palavras BIP39. Esperado 2048, obtido %d", len(bip39WordList))
	}

	fmt.Printf("✅ Dicionário carregado: %s (%d palavras)\n", getLanguageName(currentLanguage), len(bip39WordList))
}

func contains(word string) bool {
	i := sort.SearchStrings(bip39WordList, word)
	return i < len(bip39WordList) && bip39WordList[i] == word
}

func calculateChecksum(data []byte) []byte {
	firstSHA := sha256.Sum256(data)
	secondSHA := sha256.Sum256(firstSHA[:])
	return secondSHA[:4]
}

// fastChecksumValid verifica o checksum BIP39 de uma sequência de índices de
// palavras (0-2047 cada) SEM rodar PBKDF2/derivação BIP32. Isso descarta
// ~(1 - 1/2^CS) das permutações (93.75% para 12 palavras, 99.6% para 24
// palavras) usando apenas um SHA256 sobre a entropia reconstruída, que é
// ordens de magnitude mais barato que gerar o endereço completo.
func fastChecksumValid(wordIdx []int, entBits, csBits int) bool {
	n := len(wordIdx)
	entropy := make([]byte, entBits/8)

	var acc uint32
	accBits := 0
	bytePos := 0

	for i := 0; i < n; i++ {
		var bits, nbits int
		if i < n-1 {
			bits = wordIdx[i]
			nbits = 11
		} else {
			// A última palavra contribui apenas com os bits mais
			// significativos para a entropia; os bits menos
			// significativos são o próprio checksum.
			bits = wordIdx[i] >> uint(csBits)
			nbits = 11 - csBits
		}

		acc = (acc << uint(nbits)) | uint32(bits)
		accBits += nbits

		for accBits >= 8 {
			accBits -= 8
			entropy[bytePos] = byte(acc >> uint(accBits))
			bytePos++
		}
	}

	hash := sha256.Sum256(entropy)
	checksumFromHash := int(hash[0] >> uint(8-csBits))
	checksumFromWords := wordIdx[n-1] & ((1 << uint(csBits)) - 1)

	return checksumFromHash == checksumFromWords
}

func privateKeyToWIF(privateKeyBytes []byte, compressed bool) (string, error) {
	prefix := []byte{0x80}
	privateKeyBytes = append(prefix, privateKeyBytes...)

	if compressed {
		privateKeyBytes = append(privateKeyBytes, 0x01)
	}

	checksum := calculateChecksum(privateKeyBytes)
	privateKeyBytes = append(privateKeyBytes, checksum...)

	return base58.Encode(privateKeyBytes), nil
}

// generateLegacyAddress gera endereço Legacy (1...) para BIP44
func generateLegacyAddress(privateKey *btcec.PrivateKey) (string, error) {
	publicKey := privateKey.PubKey()
	compressedPubKey := publicKey.SerializeCompressed()
	pubKeyHash := btcutil.Hash160(compressedPubKey)

	versionedPayload := append([]byte{0x00}, pubKeyHash...)
	checksum := calculateChecksum(versionedPayload)
	fullPayload := append(versionedPayload, checksum...)

	return base58.Encode(fullPayload), nil
}

func deriveChildKey(masterKey *hdkeychain.ExtendedKey, path []uint32) (*hdkeychain.ExtendedKey, error) {
	currentKey := masterKey
	for _, index := range path {
		var err error
		currentKey, err = currentKey.Derive(index)
		if err != nil {
			return nil, err
		}
	}
	return currentKey, nil
}

// getBIP44Path retorna o caminho de derivação BIP44 para índice específico
func getBIP44Path(account, change, index uint32) []uint32 {
	return []uint32{
		hdkeychain.HardenedKeyStart + 44,      // purpose: BIP44
		hdkeychain.HardenedKeyStart + 0,       // coin_type: Bitcoin
		hdkeychain.HardenedKeyStart + account, // account
		change,                                // change: 0=receiving, 1=change
		index,                                 // address index
	}
}

func saveProgress(baseWords []string, currentIndex, totalPerms, keysTested int64, strategy string, priorityWords []string, currentMnemonic string, addressIndex uint32, wordCount int) error {
	derivationPath := fmt.Sprintf("m/44'/0'/0'/0/%d", addressIndex)
	progress := Progress{
		BaseWords:       baseWords,
		CurrentIndex:    currentIndex,
		TotalPerms:      totalPerms,
		KeysTested:      keysTested,
		Timestamp:       time.Now().Unix(),
		Strategy:        strategy,
		PriorityWords:   priorityWords,
		DerivationPath:  derivationPath,
		CurrentMnemonic: currentMnemonic,
		AddressIndex:    addressIndex,
		WordCount:       wordCount,
	}

	data, err := json.Marshal(progress)
	if err != nil {
		return err
	}

	return os.WriteFile(progressFile, data, 0644)
}

func loadProgress() (*Progress, error) {
	if _, err := os.Stat(progressFile); os.IsNotExist(err) {
		return nil, nil
	}

	data, err := os.ReadFile(progressFile)
	if err != nil {
		return nil, err
	}

	var progress Progress
	if err := json.Unmarshal(data, &progress); err != nil {
		return nil, err
	}

	return &progress, nil
}

func formatMnemonicPreview(mnemonic string) string {
	words := strings.Fields(mnemonic)
	if len(words) <= 3 {
		return mnemonic
	}
	return strings.Join(words[len(words)-3:], " ")
}

var factorialMemo = sync.Map{}

func factorial(n int) int64 {
	if n <= 1 {
		return 1
	}

	if val, ok := factorialMemo.Load(n); ok {
		return val.(int64)
	}

	result := int64(n) * factorial(n-1)
	factorialMemo.Store(n, result)
	return result
}

type GenerationStrategy int

const (
	StrategySequential GenerationStrategy = iota
	StrategyPriorityFirst
	StrategyBinarySplit
	StrategyMonteCarlo
)

// PermCandidate é uma mnemonic com checksum BIP39 válido, pronta para ir aos
// workers, junto com o rank (posição) dela no espaço total de permutações -
// usado para progresso/ETA/resume.
type PermCandidate struct {
	mnemonic string
	rank     int64
}

type SmartPermutationGenerator struct {
	words        []string
	wordBip39Idx []int // wordBip39Idx[i] = índice (0-2047) de words[i] na wordlist BIP39
	totalPerms   int64
	currentIndex int64
	strategy     GenerationStrategy
	priority     []string
	entBits      int
	csBits       int
}

func NewSmartPermutationGenerator(words []string, startIndex int64, strategy GenerationStrategy, priorityWords []string) *SmartPermutationGenerator {
	n := len(words)
	bip39Idx := make([]int, n)
	for i, w := range words {
		bip39Idx[i] = wordToIndex[w]
	}

	csBits := checksumBitsForWordCount[n]
	entBits := 11*n - csBits

	return &SmartPermutationGenerator{
		words:        words,
		wordBip39Idx: bip39Idx,
		totalPerms:   factorial(n),
		currentIndex: startIndex,
		strategy:     strategy,
		priority:     priorityWords,
		entBits:      entBits,
		csBits:       csBits,
	}
}

// checksumOK testa o checksum BIP39 de uma permutação dada por índices LOCAIS
// (posições 0..n-1 dentro de spg.words), sem alocar strings nem rodar
// PBKDF2/BIP32. Esse é o filtro que descarta a grande maioria das
// permutações antes de qualquer trabalho caro.
func (spg *SmartPermutationGenerator) checksumOK(order []int) bool {
	n := len(order)
	actual := make([]int, n)
	for i, localIdx := range order {
		actual[i] = spg.wordBip39Idx[localIdx]
	}
	return fastChecksumValid(actual, spg.entBits, spg.csBits)
}

// checksumOKWords é a mesma verificação, mas a partir das próprias palavras
// (usado pela estratégia Monte Carlo, que já trabalha com strings).
func (spg *SmartPermutationGenerator) checksumOKWords(perm []string) bool {
	n := len(perm)
	actual := make([]int, n)
	for i, w := range perm {
		actual[i] = wordToIndex[w]
	}
	return fastChecksumValid(actual, spg.entBits, spg.csBits)
}

func (spg *SmartPermutationGenerator) Generate() <-chan PermCandidate {
	ch := make(chan PermCandidate, 1000)

	go func() {
		defer close(ch)

		switch spg.strategy {
		case StrategyPriorityFirst:
			spg.generatePriorityFirst(ch)
		case StrategyBinarySplit:
			spg.generateBinarySplit(ch)
		case StrategyMonteCarlo:
			spg.generateMonteCarlo(ch)
		default:
			spg.generateSequential(ch)
		}
	}()

	return ch
}

func (spg *SmartPermutationGenerator) generateSequential(ch chan PermCandidate) {
	n := len(spg.words)
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}

	if spg.currentIndex > 0 {
		permutationFromRank(indices, spg.currentIndex)
	}

	count := spg.currentIndex
	for count < spg.totalPerms {
		if spg.checksumOK(indices) {
			perm := make([]string, n)
			for i, idx := range indices {
				perm[i] = spg.words[idx]
			}
			ch <- PermCandidate{mnemonic: strings.Join(perm, " "), rank: count}
		}
		count++

		if count >= spg.totalPerms {
			break
		}

		if !nextPermutation(indices) {
			break
		}
	}
}

func (spg *SmartPermutationGenerator) generatePriorityFirst(ch chan PermCandidate) {
	priorityIndices := make([]int, 0)

	for i, word := range spg.words {
		for _, priorityWord := range spg.priority {
			if word == priorityWord {
				priorityIndices = append(priorityIndices, i)
				break
			}
		}
	}

	if len(priorityIndices) == 0 {
		spg.generateSequential(ch)
		return
	}

	spg.generateSmartPermutations(ch, priorityIndices)
}

func (spg *SmartPermutationGenerator) generateSmartPermutations(ch chan PermCandidate, priorityIndices []int) {
	n := len(spg.words)
	indices := make([]int, n)
	for i := range indices {
		indices[i] = i
	}

	count := spg.currentIndex
	skipCount := spg.currentIndex

	for count < spg.totalPerms {
		hasPriorityClose := false
		for i := 0; i < len(priorityIndices)-1; i++ {
			for j := i + 1; j < len(priorityIndices); j++ {
				idx1 := priorityIndices[i]
				idx2 := priorityIndices[j]
				if abs(indices[idx1]-indices[idx2]) <= 2 {
					hasPriorityClose = true
					break
				}
			}
			if hasPriorityClose {
				break
			}
		}

		if hasPriorityClose || skipCount == 0 {
			if spg.checksumOK(indices) {
				perm := make([]string, n)
				for i, idx := range indices {
					perm[i] = spg.words[idx]
				}
				ch <- PermCandidate{mnemonic: strings.Join(perm, " "), rank: count}
			}
			if skipCount > 0 {
				skipCount--
			} else {
				count++
			}
		}

		if count >= spg.totalPerms {
			break
		}

		if !nextPermutation(indices) {
			break
		}
	}
}

func (spg *SmartPermutationGenerator) generateBinarySplit(ch chan PermCandidate) {
	spg.generateSequential(ch)
}

func (spg *SmartPermutationGenerator) generateMonteCarlo(ch chan PermCandidate) {
	rng := time.Now().UnixNano()

	for i := spg.currentIndex; i < spg.totalPerms && i < spg.currentIndex+1000000; i++ {
		perm := spg.generateBiasedRandomPermutation(rng + int64(i))
		if spg.checksumOKWords(perm) {
			ch <- PermCandidate{mnemonic: strings.Join(perm, " "), rank: i}
		}
	}
}

func (spg *SmartPermutationGenerator) generateBiasedRandomPermutation(seed int64) []string {
	n := len(spg.words)
	perm := make([]string, n)
	copy(perm, spg.words)

	rng := seed
	for i := n - 1; i > 0; i-- {
		j := int(rng % int64(i+1))

		isPriorityI := false
		isPriorityJ := false

		for _, p := range spg.priority {
			if perm[i] == p {
				isPriorityI = true
			}
			if perm[j] == p {
				isPriorityJ = true
			}
		}

		if isPriorityI && !isPriorityJ && rng%3 != 0 {
			continue
		}

		perm[i], perm[j] = perm[j], perm[i]
		rng = (rng*1664525 + 1013904223) % (1 << 31)
	}

	return perm
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func permutationFromRank(arr []int, rank int64) {
	n := len(arr)
	for i := 0; i < n; i++ {
		divisor := factorial(n - 1 - i)
		index := int(rank / divisor)
		rank %= divisor

		arr[i], arr[i+index] = arr[i+index], arr[i]
		sort.Ints(arr[i+1:])
	}
}

func nextPermutation(arr []int) bool {
	n := len(arr)
	if n <= 1 {
		return false
	}

	k := n - 2
	for k >= 0 && arr[k] >= arr[k+1] {
		k--
	}
	if k < 0 {
		return false
	}

	l := n - 1
	for arr[k] >= arr[l] {
		l--
	}

	arr[k], arr[l] = arr[l], arr[k]

	for i, j := k+1, n-1; i < j; i, j = i+1, j-1 {
		arr[i], arr[j] = arr[j], arr[i]
	}

	return true
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func saveFound(mnemonic, wif, address, passphrase, derivationPath string) error {
	file, err := os.OpenFile("found.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	entry := fmt.Sprintf(`[Encontrado em: %s]
Endereço: %s
Mnemonic: %s
Passphrase: %s
WIF: %s
Derivation: %s

-------------------------
`, timestamp, address, mnemonic, passphrase, wif, derivationPath)

	_, err = file.WriteString(entry)
	return err
}

// generateAddressFromMnemonicBIP44 gera endereço Legacy para índice específico
func generateAddressFromMnemonicBIP44(mnemonic, passphrase string, addressIndex uint32) (string, error) {
	seed := bip39.NewSeed(mnemonic, passphrase)
	masterKey, err := hdkeychain.NewMaster(seed, netParams)
	if err != nil {
		return "", err
	}

	path := getBIP44Path(0, 0, addressIndex)
	childKey, err := deriveChildKey(masterKey, path)
	if err != nil {
		return "", err
	}

	privateKey, err := childKey.ECPrivKey()
	if err != nil {
		return "", err
	}

	return generateLegacyAddress(privateKey)
}

func chooseOptimalStrategy(words []string, priorityWords []string) GenerationStrategy {
	if len(priorityWords) >= 2 {
		return StrategyPriorityFirst
	}

	if len(words) <= 8 {
		return StrategySequential
	}

	return StrategyMonteCarlo
}

func getAddressIndexFromUser() uint32 {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("🔢 Digite o índice do endereço para testar (0, 1, 2, ...): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			fmt.Println("✅ Usando índice padrão: 0")
			return 0
		}

		index, err := strconv.Atoi(input)
		if err != nil || index < 0 {
			fmt.Println("❌ Por favor, digite um número válido (0 ou maior)")
			continue
		}

		return uint32(index)
	}
}

func getTargetAddressFromUser() string {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("👉 Digite o endereço alvo BIP44 (1...): ")
		targetAddress, _ := reader.ReadString('\n')
		targetAddress = strings.TrimSpace(targetAddress)

		if targetAddress == "" {
			fmt.Println("❌ Endereço não pode estar vazio")
			continue
		}

		// Validação básica do endereço Bitcoin
		if !strings.HasPrefix(targetAddress, "1") && !strings.HasPrefix(targetAddress, "3") && !strings.HasPrefix(targetAddress, "bc1") {
			fmt.Println("⚠️  Aviso: Endereço não parece ser um endereço Bitcoin válido")
			fmt.Print("💡 Deseja continuar mesmo assim? (s/n): ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.TrimSpace(strings.ToLower(confirm))
			if confirm != "s" && confirm != "sim" {
				continue
			}
		}

		return targetAddress
	}
}

func getMnemonicWordsFromUser() []string {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("👉 Digite suas palavras (12, 15, 18, 21 ou 24) separadas por espaço: ")
		wordLine, _ := reader.ReadString('\n')
		wordLine = strings.TrimSpace(wordLine)
		words := strings.Fields(wordLine)

		validLengths := map[int]bool{12: true, 15: true, 18: true, 21: true, 24: true}
		if !validLengths[len(words)] {
			fmt.Printf("❌ Número inválido de palavras. Use 12, 15, 18, 21 ou 24 palavras. Você forneceu: %d\n", len(words))
			continue
		}

		// Validar palavras no dicionário BIP39
		var invalidWords []string
		var validWords []string

		for _, word := range words {
			if contains(word) {
				validWords = append(validWords, word)
			} else {
				invalidWords = append(invalidWords, word)
			}
		}

		if len(invalidWords) > 0 {
			fmt.Printf("❌ Palavras não encontradas no dicionário BIP39: %v\n", invalidWords)
			fmt.Print("💡 Deseja continuar mesmo assim? (s/n): ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.TrimSpace(strings.ToLower(confirm))
			if confirm != "s" && confirm != "sim" {
				continue
			}
			return words // Retorna todas as palavras mesmo com inválidas se usuário confirmar
		}

		return validWords
	}
}

func getPassphraseFromUser() string {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("🔐 Digite a passphrase (Enter para nenhuma): ")
	passphrase, _ := reader.ReadString('\n')
	return strings.TrimSpace(passphrase)
}

func completeAndSearch(words []string, target, passphrase string, numCores int, continueFromLast bool, addressIndex uint32) {
	var validWords []string

	for _, word := range words {
		if contains(word) {
			validWords = append(validWords, word)
		} else {
			fmt.Printf("⚠️  Palavra não encontrada no dicionário: '%s'\n", word)
		}
	}

	wordCount := len(validWords)
	validLengths := map[int]bool{12: true, 15: true, 18: true, 21: true, 24: true}
	if !validLengths[wordCount] {
		fmt.Printf("❌ Número inválido de palavras válidas: %d. Use 12, 15, 18, 21 ou 24 palavras.\n", wordCount)
		return
	}

	// 🔍 TESTE DIRETO com índice específico
	testMnemonic := strings.Join(validWords, " ")
	derivationPath := fmt.Sprintf("m/44'/0'/0'/0/%d", addressIndex)

	fmt.Printf("\n🔍 TESTE DIRETO BIP44:\n")
	fmt.Printf("Frase: %s\n", testMnemonic)
	fmt.Printf("Alvo:  %s\n", target)
	fmt.Printf("Índice: %d\n", addressIndex)
	fmt.Printf("Caminho: %s\n", derivationPath)
	fmt.Printf("Número de palavras: %d\n", wordCount)

	address, err := generateAddressFromMnemonicBIP44(testMnemonic, passphrase, addressIndex)
	if err != nil {
		fmt.Printf("⚠️ Erro ao gerar endereço: %v\n", err)
	} else {
		fmt.Printf("Endereço gerado: %s\n", address)
		if address == target {
			fmt.Println("🎉✅ FRASE CORRETA ENCONTRADA NO TESTE DIRETO!")

			// Gerar WIF
			seed := bip39.NewSeed(testMnemonic, passphrase)
			masterKey, _ := hdkeychain.NewMaster(seed, netParams)
			path := getBIP44Path(0, 0, addressIndex)
			childKey, _ := deriveChildKey(masterKey, path)
			privateKey, _ := childKey.ECPrivKey()
			wif, _ := privateKeyToWIF(privateKey.Serialize(), true)

			saveFound(testMnemonic, wif, address, passphrase, derivationPath)
			return
		} else {
			fmt.Println("❌ Frase incorreta - iniciando permutações...")
		}
	}

	fmt.Printf("\n✅ %d palavras válidas. Iniciando busca BIP44...\n", wordCount)
	fmt.Printf("🔍 Alvo: %s\n", target)
	fmt.Printf("🔐 Passphrase: '%s'\n", passphrase)
	fmt.Printf("📍 Derivação: %s\n", derivationPath)

	totalPermutations := factorial(len(validWords))
	fmt.Printf("📊 Total de permutações: %d\n", totalPermutations)

	smartScheduler.AddWordFrequency(validWords)
	priorityWords := smartScheduler.GetPriorityWords()
	fmt.Printf("🎯 Palavras prioritárias: %v\n", priorityWords)

	strategy := chooseOptimalStrategy(validWords, priorityWords)
	strategyName := "Sequencial"
	switch strategy {
	case StrategyPriorityFirst:
		strategyName = "Prioridade"
	case StrategyMonteCarlo:
		strategyName = "Monte Carlo"
	}
	fmt.Printf("🧠 Estratégia: %s\n", strategyName)

	var currentIndex int64
	var keysTested int64
	var lastMnemonic string

	if continueFromLast {
		progress, err := loadProgress()
		if err == nil && progress != nil && stringSlicesEqual(progress.BaseWords, validWords) && progress.AddressIndex == addressIndex && progress.WordCount == wordCount {
			currentIndex = progress.CurrentIndex
			keysTested = progress.KeysTested
			lastMnemonic = progress.CurrentMnemonic
			fmt.Printf("🔁 Continuando do índice %d/%d\n", currentIndex, totalPermutations)
			if lastMnemonic != "" {
				fmt.Printf("📝 Última mnemonic: %s\n", formatMnemonicPreview(lastMnemonic))
			}
		}
	}

	if numCores <= 0 || numCores > runtime.NumCPU() {
		numCores = runtime.NumCPU()
	}
	runtime.GOMAXPROCS(numCores)
	fmt.Printf("⚙️ Usando %d núcleo(s)\n", numCores)

	startTime := time.Now()
	lastSaveTime := startTime
	lastReportTime := startTime

	workChan := make(chan string, maxQueueSize)
	done := make(chan struct{})
	foundChan := make(chan struct {
		mnemonic, wif, address string
	}, 1)

	var wg sync.WaitGroup
	var once sync.Once

	// Workers que usam o índice específico
	for i := 0; i < numCores; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for {
				select {
				case <-done:
					return
				case mnemonic, ok := <-workChan:
					if !ok {
						return
					}

					// Testar com o índice específico
					address, err := generateAddressFromMnemonicBIP44(mnemonic, passphrase, addressIndex)
					if err != nil {
						continue
					}

					atomic.AddInt64(&keysTested, 1)

					if address == target {
						// ✅ ENCONTROU!
						seed := bip39.NewSeed(mnemonic, passphrase)
						masterKey, err := hdkeychain.NewMaster(seed, netParams)
						if err == nil {
							path := getBIP44Path(0, 0, addressIndex)
							childKey, err := deriveChildKey(masterKey, path)
							if err == nil {
								privateKey, err := childKey.ECPrivKey()
								if err == nil {
									wif, _ := privateKeyToWIF(privateKey.Serialize(), true)
									select {
									case foundChan <- struct {
										mnemonic, wif, address string
									}{mnemonic, wif, address}:
										once.Do(func() { close(done) })
									case <-done:
									}
									return
								}
							}
						}
					}
				}
			}
		}(i)
	}

	// Produtor
	go func() {
		defer close(workChan)

		generator := NewSmartPermutationGenerator(validWords, currentIndex, strategy, priorityWords)
		candidates := generator.Generate()

		for cand := range candidates {
			select {
			case <-done:
				return
			case workChan <- cand.mnemonic:
				// currentIndex é a RANK (posição) da permutação, não uma
				// contagem de itens enviados: o filtro de checksum pula a
				// maioria das permutações sem sequer chegar aqui, então
				// usamos o rank para refletir o progresso real.
				currentIndex = cand.rank + 1
				lastMnemonic = cand.mnemonic

				if time.Since(lastSaveTime) > progressSaveSec*time.Second {
					if err := saveProgress(validWords, currentIndex, totalPermutations, keysTested, strategyName, priorityWords, lastMnemonic, addressIndex, wordCount); err != nil {
						fmt.Printf("⚠️ Erro ao salvar progresso: %v\n", err)
					} else {
						lastSaveTime = time.Now()
					}
				}

				if time.Since(lastReportTime) > 5*time.Second {
					elapsed := time.Since(startTime).Seconds()
					currentKeys := atomic.LoadInt64(&keysTested)

					// scanSpeed: permutações avaliadas por segundo (inclui as
					// que foram descartadas pelo checksum). É o que determina
					// o ETA real, já que a maior parte do espaço é eliminada
					// sem gerar endereço.
					scanSpeed := float64(currentIndex) / elapsed
					// deriveSpeed: quantos endereços completos por segundo
					// realmente são derivados (checksum válido).
					deriveSpeed := float64(currentKeys) / elapsed

					progressPercent := float64(currentIndex) / float64(totalPermutations) * 100
					remaining := float64(totalPermutations-currentIndex) / scanSpeed

					fmt.Printf("⚡ %d/%d (%.2f%%) | scan: %.0f/s | válidas: %.0f/s | ETA: %.1fh | %s\n",
						currentIndex, totalPermutations, progressPercent, scanSpeed, deriveSpeed,
						remaining/3600, formatMnemonicPreview(cand.mnemonic))
					lastReportTime = time.Now()
				}
			}
		}
	}()

	wg.Wait()

	select {
	case result := <-foundChan:
		derivationPath := fmt.Sprintf("m/44'/0'/0'/0/%d", addressIndex)
		fmt.Println("\n----- 🎉 ENCONTRADO! -----")
		fmt.Printf("📝 Mnemonic: %s\n", result.mnemonic)
		fmt.Printf("🎯 Endereço: %s\n", result.address)
		fmt.Printf("🔐 Passphrase: %s\n", passphrase)
		fmt.Printf("🔑 WIF: %s\n", result.wif)
		fmt.Printf("📍 Derivação: %s\n", derivationPath)
		fmt.Printf("📊 Índice usado: %d\n", addressIndex)
		fmt.Printf("🔢 Número de palavras: %d\n", wordCount)

		if err := saveFound(result.mnemonic, result.wif, result.address, passphrase, derivationPath); err != nil {
			fmt.Printf("⚠️ Erro ao salvar: %v\n", err)
		} else {
			fmt.Println("✅ Dados salvos em 'found.txt'")
		}

		os.Remove(progressFile)
		return

	default:
		fmt.Printf("\n❌ Nenhuma permutação encontrou o endereço alvo no índice %d.\n", addressIndex)
		fmt.Printf("💡 Tente executar novamente com um índice diferente.\n")
		if err := saveProgress(validWords, currentIndex, totalPermutations, keysTested, strategyName, priorityWords, lastMnemonic, addressIndex, wordCount); err != nil {
			fmt.Printf("⚠️ Erro ao salvar progresso final: %v\n", err)
		}
	}
}

func menu() {
	fmt.Println("=== Bitcoin Address Recovery Tool ===")
	fmt.Println()

	// Obter endereço alvo
	targetAddress := getTargetAddressFromUser()

	// Obter palavras mnemônicas
	words := getMnemonicWordsFromUser()

	// Obter passphrase
	passphrase := getPassphraseFromUser()

	// Obter índice do endereço
	addressIndex := getAddressIndexFromUser()

	// Configuração de núcleos
	availableCores := runtime.NumCPU()
	fmt.Printf("🧠 Núcleos disponíveis: %d\n", availableCores)

	var numCores int
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("🔧 Quantos núcleos usar (1-%d, Enter para todos)? ", availableCores)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "" {
			numCores = availableCores
			break
		}
		_, err := fmt.Sscanf(input, "%d", &numCores)
		if err != nil || numCores < 1 || numCores > availableCores {
			fmt.Printf("❌ Use um número entre 1 e %d.\n", availableCores)
			continue
		}
		break
	}

	// Continuar de onde parou
	var continueFromLast bool
	fmt.Print("🔁 Continuar de onde parou? (s/n): ")
	contInput, _ := reader.ReadString('\n')
	continueFromLast = strings.ToLower(strings.TrimSpace(contInput)) == "s"

	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("🚀 INICIANDO BUSCA...")
	fmt.Println(strings.Repeat("=", 50))

	// Iniciar busca
	completeAndSearch(words, targetAddress, passphrase, numCores, continueFromLast, addressIndex)
}

func main() {
	fmt.Println(login)
	menu()
}
