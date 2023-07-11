package globalhelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/labstack/echo"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"gorm.io/gorm"

	"github.com/golangid/candi/candihelper"
	"github.com/golangid/candi/codebase/interfaces"
	"github.com/golangid/candi/config/env"

	"github.com/google/jsonapi"
)

const (
	// ErrorDataNotFound error message when data doesn't exist
	ErrorDataNotFound = "data tidak ditemukan"
	// CHARS for setting short random string
	CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"
	// NUMBERS for setting short random number
	NUMBERS = "0123456789"

	// PayloadInvalid constanta
	PayloadInvalid = "payload %s is invalid"

	// this block is for validating URL format
	email        string = "^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$"
	ip           string = `(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`
	urlSchema    string = `((ftp|sftp|tcp|udp|wss?|https?):\/\/)`
	urlUsername  string = `(\S+(:\S*)?@)`
	urlPath      string = `((\/|\?|#)[^\s]*)`
	urlPort      string = `(:(\d{1,5}))`
	urlIP        string = `([1-9]\d?|1\d\d|2[01]\d|22[0-3])(\.(1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.([0-9]\d?|1\d\d|2[0-4]\d|25[0-4]))`
	urlSubdomain string = `((www\.)|([a-zA-Z0-9]([-\.][-\._a-zA-Z0-9]+)*))`
	urlPattern   string = `^` + urlSchema + `?` + urlUsername + `?` + `((` + urlIP + `|(\[` + ip + `\])|(([a-zA-Z0-9]([a-zA-Z0-9-_]+)?[a-zA-Z0-9]([-\.][a-zA-Z0-9]+)*)|(` + urlSubdomain + `?))?(([a-zA-Z\x{00a1}-\x{ffff}0-9]+-?-?)*[a-zA-Z\x{00a1}-\x{ffff}0-9]+)(?:\.([a-zA-Z\x{00a1}-\x{ffff}]{1,}))?))\.?` + urlPort + `?` + urlPath + `?$`
	area         string = `^\+\d{1,5}$`
	phone        string = `^\d{5,}$`
)

var (
	// ErrBadFormatURL variable for error of url format
	ErrBadFormatURL = errors.New("invalid url format")
	// ErrBadFormatMail variable for error of email format
	ErrBadFormatMail = errors.New("invalid email format")
	// ErrBadFormatPhoneNumber variable for error of email format
	ErrBadFormatPhoneNumber = errors.New("invalid phone format")

	// emailRegexp regex for validate email
	emailRegexp = regexp.MustCompile(email)
	// urlRegexp regex for validate URL
	urlRegexp = regexp.MustCompile(urlPattern)
	// areaRegexp  regex for phone area number using +
	areaRegexp = regexp.MustCompile(area)
	// telpRegexp regex for phone number
	phoneRegexp = regexp.MustCompile(phone)
	// camel regex for string camelcase
	camel = regexp.MustCompile("(^[^A-Z]*|[A-Z]*)([A-Z][^A-Z]+|$)")

	// domains for list domain validate
	domains = new(collection)
)

type collection struct {
	items map[string]struct{}
	err   error
	once  sync.Once
}

type commonJSONAuth struct {
	Email        string `json:"email"`
	Pass         string `json:"password"`
	FirstName    string `json:"firstName,omitempty"`
	LastName     string `json:"lastName,omitempty"`
	BirthDate    string `json:"birthDate,omitempty"`
	Mobile       string `json:"mobile,omitempty"`
	RegisterType string `json:"registerType,omitempty"`
}

// ValidateEmail function for validating email
func ValidateEmail(email string) error {
	if !emailRegexp.MatchString(email) {
		return ErrBadFormatMail
	}
	return nil
}

// ValidateURL function for validating url
func ValidateURL(str string) error {
	if !urlRegexp.MatchString(str) {
		return ErrBadFormatURL
	}
	return nil
}

// ValidatePhoneNumber function for validating phone number only
func ValidatePhoneNumber(str string) error {
	if !phoneRegexp.MatchString(str) {
		return ErrBadFormatPhoneNumber
	}
	return nil
}

// ValidatePhoneAreaNumber function for validating area phone number
func ValidatePhoneAreaNumber(str string) error {
	if !areaRegexp.MatchString(str) {
		return ErrBadFormatPhoneNumber
	}
	return nil
}

// StringArrayReplace function for replacing whether string in array
// str string searched string
// list []string array
func StringArrayReplace(str string, listFind, listReplace []string) string {
	for i, v := range listFind {
		if strings.Contains(str, v) {
			str = strings.Replace(str, v, listReplace[i], -1)
		}
	}
	return str
}

// ValidateMaxInput function for validating maximum input
func ValidateMaxInput(input string, limit int) error {
	if len(input) > limit {
		err := errors.New(" value is too long")
		return err
	}

	return nil
}

// ValidateNumeric function for check valid numeric
func ValidateNumeric(str string) bool {
	var num, symbol int
	for _, r := range str {
		if r >= 48 && r <= 57 { //code ascii for [0-9]
			num = +1
		} else {
			symbol = +1
		}
	}

	if symbol > 0 {
		return false
	}

	return num >= 1
}

// ValidateAlphabet function for check alphabet
func ValidateAlphabet(str string) bool {
	var uppercase, lowercase, symbol int
	for _, r := range str {
		if IsUppercase(r) {
			uppercase = +1
		} else if IsLowercase(r) {
			lowercase = +1
		} else { //except alphabet
			symbol = +1
		}
	}

	if symbol > 0 {
		return false
	}
	return uppercase >= 1 || lowercase >= 1
}

// ValidateAlphabetWithSpace function for check alphabet with space
func ValidateAlphabetWithSpace(str string) bool {
	var uppercase, lowercase, space, symbol int
	for _, r := range str {
		if IsUppercase(r) { //code ascii for [A-Z]
			uppercase = +1
		} else if IsLowercase(r) { //code ascii for [a-z]
			lowercase = +1
		} else if r == 32 { //code ascii for space
			space = +1
		} else { //except alphabet
			symbol = +1
		}
	}

	if symbol > 0 {
		return false
	}
	return uppercase >= 1 || lowercase >= 1 || space >= 1
}

// ValidateAlphanumeric function for check valid alphanumeric
func ValidateAlphanumeric(str string, must bool) bool {
	var uppercase, lowercase, num, symbol int
	for _, r := range str {
		if IsUppercase(r) {
			uppercase = +1
		} else if IsLowercase(r) {
			lowercase = +1
		} else if IsNumeric(r) {
			num = +1
		} else {
			symbol = +1
		}
	}

	if symbol > 0 {
		return false
	}

	if must { //must alphanumeric
		return (uppercase >= 1 || lowercase >= 1) && num >= 1
	}

	return uppercase >= 1 || lowercase >= 1 || num >= 1
}

// ValidateAlphanumericWithSpace function for validating string to alpha numeric with space
func ValidateAlphanumericWithSpace(str string, must bool) bool {
	var uppercase, lowercase, num, space, symbol int
	for _, r := range str {
		if IsUppercase(r) { //code ascii for [A-Z]
			uppercase = +1
		} else if IsLowercase(r) { //code ascii for [a-z]
			lowercase = +1
		} else if IsNumeric(r) { //code ascii for [0-9]
			num = +1
		} else if r == 32 { //code ascii for space
			space = +1
		} else {
			symbol = +1
		}
	}

	if symbol > 0 {
		return false
	}

	if must { //must alphanumeric
		return (uppercase >= 1 || lowercase >= 1) && num >= 1 && space >= 1
	}

	return (uppercase >= 1 || lowercase >= 1 || num >= 1) || space >= 1
}

// GenerateRandomID function for generating  ID
func GenerateRandomID(length int, prefix ...string) string {
	var strPrefix string

	if len(prefix) > 0 {
		strPrefix = prefix[0]
	}

	yearNow, monthNow, _ := time.Now().Date()
	year := strconv.Itoa(yearNow)[2:len(strconv.Itoa(yearNow))]
	month := int(monthNow)
	RandomString := RandomString(length)

	id := fmt.Sprintf("%s%s%d%s", strPrefix, year, month, RandomString)
	return id
}

// RandomString function for random string
func RandomString(length int) string {
	rand.Seed(time.Now().UTC().UnixNano())

	charsLength := len(CHARS)
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = CHARS[rand.Intn(charsLength)]
	}
	return string(result)
}

// RandomNumber function for random number
func RandomNumber(length int) string {
	rand.Seed(time.Now().UTC().UnixNano())

	charsLength := len(NUMBERS)
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = NUMBERS[rand.Intn(charsLength)]
	}
	return string(result)
}

// StringInSlice function for checking whether string in slice
// str string searched string
// list []string slice
func StringInSlice(str string, list []string, caseSensitive ...bool) bool {
	isCaseSensitive := true
	if len(caseSensitive) > 0 {
		isCaseSensitive = caseSensitive[0]
	}

	if isCaseSensitive {
		for _, v := range list {
			if v == str {
				return true
			}
		}
	} else {
		for _, v := range list {
			if strings.ToLower(v) == strings.ToLower(str) {
				return true
			}
		}
	}

	return false
}

// GetProtocol function for getting http protocol based on TLS
// isTLS bool
func GetProtocol(isTLS bool) string {
	// check tls first to get protocol
	if isTLS {
		return "https://"
	}
	return "http://"
}

// GetHostURL function for getting host of any URL
func GetHostURL(req *http.Request) string {
	return fmt.Sprintf("%s%s", GetProtocol(req.TLS != nil), req.Host)
}

// GetSelfLink function to get self link
func GetSelfLink(req *http.Request) string {
	return fmt.Sprintf("%s%s", GetHostURL(req), req.RequestURI)
}

// MarshalConvertManyPayload function to convert struct response to jsonapi.manypayload so that we can add meta or link data
func MarshalConvertManyPayload(structResponse interface{}) (payload *jsonapi.ManyPayload, err error) {
	// set response marshal jsonapi struct
	p, err := jsonapi.Marshal(structResponse)
	if err != nil {
		return nil, err
	}

	var ok bool
	if payload, ok = p.(*jsonapi.ManyPayload); !ok {
		err = fmt.Errorf(PayloadInvalid, "many payload")
		return nil, err
	}

	return
}

// MarshalConvertOnePayload function to convert struct response to jsonapi.OnePayLoad so that we can add meta or link data
func MarshalConvertOnePayload(structResponse interface{}) (payload *jsonapi.OnePayload, err error) {
	// set response marshal jsonapi struct
	p, err := jsonapi.Marshal(structResponse)
	if err != nil {
		return nil, err
	}

	var ok bool
	if payload, ok = p.(*jsonapi.OnePayload); !ok {
		err = fmt.Errorf(PayloadInvalid, "one payload")
		return nil, err
	}

	return
}

func getMaskedPassword() string {
	return "xxxxx"
}

// MaskPassword for mask password string
func MaskPassword(s string) string {
	splitText := strings.Split(s, "&")

	var newText string
	for i, text := range splitText {

		password := strings.Index(text, "password=")
		if password > -1 {
			text = strings.Join([]string{"password=", getMaskedPassword()}, "")
		}

		newPassword := strings.Index(text, "newPassword=")
		if newPassword > -1 {
			text = strings.Join([]string{"newPassword=", getMaskedPassword()}, "")
		}

		rePassword := strings.Index(text, "rePassword=")
		if rePassword > -1 {
			text = strings.Join([]string{"rePassword=", getMaskedPassword()}, "")
		}

		if i < 1 {
			newText = text
		} else {
			newText = newText + "&" + text
		}

	}
	return newText
}

// IsUppercase reusable rune check if char is uppercase
func IsUppercase(r rune) bool {
	return int(r) >= 65 && int(r) <= 90
}

// IsLowercase reusable rune check if char is lowercase
func IsLowercase(r rune) bool {
	return int(r) >= 97 && int(r) <= 122
}

// IsNumeric reusable rune check if char is numeric
func IsNumeric(r rune) bool {
	return int(r) >= 48 && int(r) <= 57
}

// IsAllowedSymbol check if rune is any of
// [space, coma, ., !, ", #, $, %, &, ', (, ), *, +, -, /, :, ;, <, =, >, ?, @, [, \, ], ^, _, `, {, |, }, ~]
func IsAllowedSymbol(r rune) bool {
	m := int(r)
	return m >= 32 && m <= 47 || m >= 58 && m <= 64 || m >= 91 && m <= 96 || m >= 123 && m <= 126
}

// ValidateLatinOnly func for check valid latin only
func ValidateLatinOnly(str string) bool {
	var uppercase, lowercase, num, allowed, symbol int
	for _, r := range str {
		if IsUppercase(r) {
			uppercase = +1
		} else if IsLowercase(r) {
			lowercase = +1
		} else if IsNumeric(r) {
			num = +1
		} else if IsAllowedSymbol(r) {
			allowed = +1
		} else {
			symbol = +1
		}
	}

	if symbol > 0 {
		return false
	}

	return uppercase >= 1 || lowercase >= 1 || num >= 1 || allowed >= 0
}

// CamelToLowerCase func for replace camel to lower case
func CamelToLowerCase(s string) string {
	var a []string
	for _, sub := range camel.FindAllStringSubmatch(s, -1) {
		if sub[1] != "" {
			a = append(a, sub[1])
		}
		if sub[2] != "" {
			a = append(a, sub[2])
		}
	}
	return strings.ToLower(strings.Join(a, " "))
}

// MergeMaps func to merge map[string]interface{}
func MergeMaps(map1, map2 map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range map1 {
		result[k] = v
	}

	for k, v := range map2 {
		result[k] = v
	}

	return result
}

// IsDisabledEmail for split and validate email domain
func IsDisabledEmail(email string) bool {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return false
	}
	return IsDisabledDomain(parts[1])
}

// IsDisabledDomain for validate domain
func IsDisabledDomain(domain string) bool {
	domains.once.Do(func() { domains.loadDomainList() })
	if domains.err != nil {
		return false
	}
	domain = strings.TrimSpace(domain)
	return domains.hasValidDomain(strings.ToLower(domain))
}

func (c *collection) hasValidDomain(item string) bool {
	_, ok := c.items[item]
	return ok
}

func (c *collection) loadDomainList() {
	c.items = make(map[string]struct{})
	for _, value := range DisposableDomains {
		c.items[value] = struct{}{}
	}
}

// MaskJSONPassword mask password sent on JSON format
func MaskJSONPassword(body []byte) []byte {
	dest := commonJSONAuth{}
	if err := json.Unmarshal(body, &dest); err == nil && dest.Email != "" && dest.Pass != "" {
		dest.Pass = "xxxxx"
		out, _ := json.Marshal(dest)
		return out

	}
	return body
}

func ToString(v interface{}) (s string) {
	switch val := v.(type) {
	case error:
		if val != nil {
			s = val.Error()
		}
	case string:
		s = val
	case int:
		s = strconv.Itoa(val)
	default:
		b, _ := json.Marshal(val)
		s = string(b)
	}
	return
}

// PtrTimeToString helper
func PtrTimeToString(t *time.Time) string {
	if t == nil {
		return ""
	}
	return candihelper.ToAsiaJakartaTime(*t).Format(time.RFC3339)
}

// ConstructSoftDelete helper
func ConstructSoftDelete() map[string]interface{} {
	return map[string]interface{}{
		"deleted_at": time.Now(),
	}
}

// ToStringSlice helper
func ToStringSlice(i []int) (res []string) {
	for _, id := range i {
		res = append(res, strconv.Itoa(id))
	}
	return
}

// ChunkString helper
func ChunkString(s string, chunkSize int) []string {
	var chunks []string
	runes := []rune(s)

	if len(runes) == 0 {
		return []string{s}
	}

	for i := 0; i < len(runes); i += chunkSize {
		nn := i + chunkSize
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}
	return chunks
}

// LeftPad function to insert left pad with total length should >= totalLen
func LeftPad(str string, pad string, totalLen int) (resStr string) {
	resStr = str
	for i := len(str); i < totalLen; i++ {
		resStr = pad + resStr
	}
	return
}

// StringArrayToArrayOfInt to convert string array (from database type varchar) to array of integer
func StringArrayToArrayOfInt(str string) (arrInt []int, err error) {
	if str == "" {
		return nil, nil
	}
	newStr := str[1:strings.LastIndex(str, "}")]
	arrStr := strings.Split(newStr, ",")
	for _, str := range arrStr {
		intStr, err := strconv.Atoi(str)
		if err != nil {
			return nil, err
		}
		arrInt = append(arrInt, intStr)
	}

	return arrInt, err
}

// StringArrayToArrayOfString to convert string array (from database type varchar) to array of string
func StringArrayToArrayOfString(str string) (arr []string) {
	if str == "" {
		return
	}
	newStr := str[1:strings.LastIndex(str, "}")]
	arrStr := strings.Split(newStr, ",")
	for _, str := range arrStr {
		arr = append(arr, str)
	}

	return
}

// IntInSlice helper
func IntInSlice(i int, sl []int) bool {
	for _, s := range sl {
		if i == s {
			return true
		}
	}
	return false
}

// AppendUniqueString function only append element to slice of string if value unique
func AppendUniqueString(slice []string, str string) []string {
	for _, ele := range slice {
		if ele == str {
			return slice
		}
	}

	return append(slice, str)
}

// AppendUniqueInt function only append element to slice of int if value unique
func AppendUniqueInt(slice []int, str int) []int {
	for _, ele := range slice {
		if ele == str {
			return slice
		}
	}

	return append(slice, str)
}

// SplitObjects helpeer
func SplitObjects(objArr []interface{}, size int) [][]interface{} {
	var chunkSet [][]interface{}
	var chunk []interface{}

	for len(objArr) > size {
		chunk, objArr = objArr[:size], objArr[size:]
		chunkSet = append(chunkSet, chunk)
	}
	if len(objArr) > 0 {
		chunkSet = append(chunkSet, objArr[:])
	}

	return chunkSet
}

// SortedKeys Enable map keys to be retrieved in same order when iterating
func SortedKeys(val map[string]interface{}) []string {
	var keys []string
	for key := range val {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// ContainString Check if string value is contained in slice
func ContainString(s []string, value string) bool {
	for _, v := range s {
		if v == value {
			return true
		}
	}
	return false
}

// ToPercentage Convert to percentage value
func ToPercentage(pembilang, penyebut float64, allowMinus bool) (percentage float64) {
	if penyebut == 0 {
		return
	}

	persentase := float64(pembilang/penyebut) * 100
	percentage = math.Round(persentase*100) / 100

	if percentage > 100 {
		percentage = 100
	} else if percentage < 0 && !allowMinus {
		percentage = 0
	}

	return
}

// MakeMustFilter helper
func MakeMustFilter(fields ...string) map[string]bool {
	mp := map[string]bool{}
	for _, f := range fields {
		mp[f] = true
	}

	return mp
}

// NumberToString helper
func NumberToString(n int, sep rune) string {

	s := strconv.Itoa(n)

	startOffset := 0
	if n < 0 {
		startOffset = 1
	}

	const groupLen = 3
	groups := (len(s) - startOffset - 1) / groupLen

	if groups == 0 {
		return s
	}

	sepLen := utf8.RuneLen(sep)
	sepBytes := make([]byte, sepLen)
	_ = utf8.EncodeRune(sepBytes, sep)

	buf := make([]byte, groups*(groupLen+sepLen)+len(s)-(groups*groupLen))

	startOffset += groupLen
	p := len(s)
	q := len(buf)
	for p > startOffset {
		p -= groupLen
		q -= groupLen
		copy(buf[q:q+groupLen], s[p:])
		q -= sepLen
		copy(buf[q:], sepBytes)
	}
	if q > 0 {
		copy(buf[:q], s)
	}
	return string(buf)
}

// EchoValidateQueryParam helper
func EchoValidateQueryParam(c echo.Context, param interface{}, schemaID string, validator interfaces.Validator) error {
	multiError := candihelper.NewMultiError()
	if err := candihelper.ParseFromQueryParam(c.Request().URL.Query(), param); err != nil {
		multiError = multiError.Append("parse query", err)
		return multiError
	}

	if err := validator.ValidateDocument(schemaID, param); err != nil {
		multiError = multiError.Append("validate url param", err)
		return multiError
	}
	return nil
}

// EchoValidateBodyParam : validate echo request body parameter
func EchoValidateBodyParam(c echo.Context, param interface{}, schemaID string, validator interfaces.Validator) error {
	var (
		multiError = candihelper.NewMultiError()
		bodyBytes  []byte
	)
	if c.Request().Body != nil {
		var errBody error
		bodyBytes, errBody = ioutil.ReadAll(c.Request().Body)
		if errBody != nil {
			multiError.Append("body reader", errBody)
			return multiError
		}
	}

	if errValidator := validator.ValidateDocument(schemaID, bodyBytes); errValidator != nil {
		multiError.Append("validate body param", errValidator)
		val := errValidator.(candihelper.MultiError).ToMap()
		if len(val) > 1 {
			multiError.Clear()
			for key, errs := range val {
				multiError.Append("validate body param "+key, errors.New(errs))
			}
		} else {
			multiError.Append("validate body param", errValidator)
		}
		return multiError
	}

	if errJson := json.Unmarshal(bodyBytes, param); errJson != nil {
		multiError.Append("unmarshal param", errJson)
		return multiError
	}

	return nil
}

// EchoValidateQueryParamSingle : validate echo request url query parameter (single error)
func EchoValidateQueryParamSingle(c echo.Context, param interface{}, schemaID string, validator interfaces.Validator) error {
	if err := candihelper.ParseFromQueryParam(c.Request().URL.Query(), param); err != nil {
		return err
	}
	if err := validator.ValidateDocument(schemaID, param); err != nil {
		return err
	}
	return nil
}

// ParseAndValidateID helper
func ParseAndValidateID(str string) (id int, err error) {

	id, err = strconv.Atoi(str)
	if err != nil {
		return id, errors.New("cannot parse to type number")
	}
	if id > math.MaxInt32 {
		return id, errors.New("Invalid ID")
	}
	if id <= 0 {
		return id, errors.New("ID cannot less or equal than 0")
	}
	return
}

// WrapErrorGormNotFound helper
func WrapErrorGormNotFound(err error, wrapError error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return wrapError
	}
	return err
}

// PanicWhenError helper
func PanicWhenError(err error) {
	if err != nil {
		panic(err)
	}
}

// RecoverPanic helper
func RecoverPanic(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("%v", r)
	}
	return
}

// GetIPAddress helper
func GetIPAddress() string {
	address, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, a := range address {
		if ipNet, ok := a.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}

	return ""
}

func CamelToLowerSnakeCase(str string) string {
	var matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
	var matchAllCap = regexp.MustCompile("([a-z0-9])([A-Z])")

	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")
	return strings.ToLower(snake)
}

func IsValidMongoObjectID(input string) bool {
	return primitive.IsValidObjectID(input)
}

func GetTitleByEnv(title string) string {
	switch env.BaseEnv().Environment {
	case "production":
		return title
	case "sanity":
		return "[SANITY] " + title
	default:
		return "[DEV] " + title
	}
}

func ChangeMessageByCondition(condition string, listCondition []string, defaultMessage string, customMessage string) string {
	output := defaultMessage

	if len(customMessage) == 0 {
		return output
	}

	if candihelper.StringInSlice(condition, listCondition) {
		output = customMessage
		return output
	}

	return customMessage
}

func SingleMultiError(key string, err error) candihelper.MultiError {
	resp := candihelper.NewMultiError()
	resp.Append(key, err)
	return resp
}

func ValidateDateFormat(layout string, date string) error {
	if len(date) == 0 {
		return nil
	}

	_, err := time.Parse(layout, date)
	if err != nil {
		return errors.New("Please use format dd-mm-YYYY for DoB")
	}

	return nil
}

func ChangeDateFormat(layoutFrom string, layoutTo string, date string) (formatedDate string, err error) {
	validDate, err := time.Parse(layoutFrom, date)
	if err != nil {
		return formatedDate, err
	}

	return validDate.Format(layoutTo), nil
}

func CompareDate(comparison, firstDate, secondDate string) bool {
	start, _ := time.Parse("02-01-2006", firstDate)
	end, _ := time.Parse("02-01-2006", secondDate)

	switch comparison {
	case ">=":
		return start.After(end) || start.Equal(end)
	case "<=":
		return start.Before(end) || start.Equal(end)
	default:
		return start.Before(end) || start.Equal(end)
	}
}
