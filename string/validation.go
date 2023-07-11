package string

import (
	"errors"
	"regexp"
	"strconv"
	"time"
)

const (
	errorBadFormat = string("this field value is in bad format")
	errorNumber    = string("this field value should be Number")
	errorAlphabet  = string("this field value should be alphabetical")
)

var (
	numberPattern        = regexp.MustCompile("^[0-9]+$")
	alphabetPattern      = regexp.MustCompile("^[A-Za-z ]+$")
	alphabetEmptyPattern = regexp.MustCompile("^[A-Za-z]*$")
	nonEnglishCharacter  = regexp.MustCompile("[^\x00-\x7F]+")
	emailPattern         = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,4}$`)
	alphanumericPattern  = regexp.MustCompile(`^[A-Za-z0-9.,\\;\\_\\&\\/\-\(\\)\\:\\'\\\ ]+$`)
)

// IsValidEmail check if string is email
func IsValidEmail(input string) bool {
	check := emailPattern.MatchString
	return check(input)
}

// IsValidBirthDate check if given date is date and older than 1 day
func IsValidBirthDate(dob string) bool {
	minimumDob, _ := time.ParseDuration("24h")

	birthDateTime, err := time.Parse("02/01/2006", dob)
	if err != nil {
		return false
	}

	birthDateDur := time.Since(birthDateTime)
	return birthDateDur > minimumDob
}

// IsAlphaNumeric validate string is alphanumeric
func IsAlphaNumeric(input string) bool {
	check := alphanumericPattern.MatchString
	return check(input)
}

// ValidateAlphaNumericInput function for validating alpha numeric
func ValidateAlphaNumericInput(input string) error {
	if !IsAlphaNumeric(input) {
		return errors.New(errorBadFormat)
	}
	return nil
}

// ValidateBooleanInput function for validating boolean input
func ValidateBooleanInput(input string) bool {
	return IsBool(input)
}

// IsBool function for validating boolean input
func IsBool(input string) bool {
	b, e := strconv.ParseBool(input)
	if e != nil {
		return false
	}
	return b
}

// IsUppercase check if string is in uppercase format
func IsUppercase(r rune) bool {
	return int(r) >= 65 && int(r) <= 90
}

// IsLowercase check if string is in lowercase format
func IsLowercase(r rune) bool {
	return int(r) >= 97 && int(r) <= 122
}

// IsNumeric check if string is number
func IsNumeric(r rune) bool {
	return int(r) >= 48 && int(r) <= 57
}

// IsSpecialCharacter check if character is any of
// code ascii for [space, coma, ., !, ", #, $, %, &, ', (, ), *, +, -, /, :, ;, =, ?, @, [, \, ], ^, _, `, {, |, }, ~]
// original r >= 32 && r <= 47 || r >= 58 && r <= 64 && r != 60 && r != 62 || r >= 91 && r <= 96 || r >= 123 && r <= 126
func IsSpecialCharacter(str rune) bool {
	r := int(str)
	return r >= 32 && r <= 47 || r >= 58 && r <= 64 || r >= 91 && r <= 96 || r >= 123 && r <= 126
}

// IsLGCharacter check if character is less than (<) or greater than (>)
func IsLGCharacter(str rune) bool {
	return int(str) == 60 || int(str) == 62
}

// IsCurlyBracket check if character is 123 = `{`, 125 = `}`
func IsCurlyBracket(str rune) bool {
	return int(str) == 123 || int(str) == 125
}

// ValidateGenderInput function for validating gender
func ValidateGenderInput(input string) error {
	if len(input) > 1 {
		return errors.New("this field value should be M, F or S")
	}
	check := regexp.MustCompile("^[MFS]+$").MatchString

	if !check(input) {
		return errors.New(errorBadFormat)
	}
	return nil
}

// ValidateNonEnglishCharacter function for validating string to non english
func ValidateNonEnglishCharacter(str string) error {
	if nonEnglishCharacter.MatchString(str) {
		return errors.New("character latin only allowed")
	}

	return nil
}

// ValidateNumberOnlyInput function for validating number only
func ValidateNumberOnlyInput(input string) error {
	check := numberPattern.MatchString
	if !check(input) {
		return errors.New(errorNumber)
	}
	return nil
}

// ValidateNumberOnlyInputAllowEmpty function for validating number only
// and allow empty
// same as above
func ValidateNumberOnlyInputAllowEmpty(input string) error {
	return ValidateAlphaNumericInput(input)
}

// ValidateAlphabeticalOnlyInput function for validating alphabet only
func ValidateAlphabeticalOnlyInput(input string) error {
	check := alphabetPattern.MatchString
	if !check(input) {
		return errors.New(errorAlphabet)
	}
	return nil
}

// ValidateAlphabeticalOnlyInputAllowEmpty function for validating
// alphabet only and allow empty
func ValidateAlphabeticalOnlyInputAllowEmpty(input string) error {
	check := alphabetEmptyPattern.MatchString
	if !check(input) {
		return errors.New(errorAlphabet)
	}
	return nil
}

// ValidateEmail function for validating email
func ValidateEmail(input string) error {
	if !IsValidEmail(input) {
		return errors.New("invalid email address")
	}
	return nil
}

// ValidateAlphanumeric func for check valid alphanumeric
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
		return uppercase >= 1 && lowercase >= 1 && num >= 1
	}

	return uppercase >= 1 || lowercase >= 1 || num >= 1
}

// ValidateLatinOnlyExcepTag func for check valid latin only
func ValidateLatinOnlyExcepTag(str string) bool {
	var uppercase, lowercase, num, allowed, symbol int
	for _, r := range str {
		if IsUppercase(r) {
			uppercase = +1
		} else if IsLowercase(r) {
			lowercase = +1
		} else if IsNumeric(r) {
			num = +1
		} else if r == 10 || IsSpecialCharacter(r) && !IsLGCharacter(r) {
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

// ValidateLatinOnlyExcepTagCurly func for check valid latin only
func ValidateLatinOnlyExcepTagCurly(str string) bool {
	var uppercase, lowercase, num, allowed, symbol int
	for _, r := range str {
		if IsUppercase(r) {
			uppercase = +1
		} else if IsLowercase(r) {
			lowercase = +1
		} else if IsNumeric(r) {
			num = +1
		} else if IsSpecialCharacter(r) && !IsCurlyBracket(r) && !IsLGCharacter(r) {
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
