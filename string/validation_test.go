package string

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type baseStruct struct {
	name      string
	input     string
	expected  bool
	wantError bool
	must      bool
}

var testEmailValidation = []baseStruct{
	{
		name:     "#1",
		input:    "tester@gmail.com",
		expected: true,
	},
	{
		name:     "#2",
		input:    "testgmail.com",
		expected: false,
	},
}

var testBirthdate = []baseStruct{
	{
		name:     "#1",
		input:    "17/02/1990",
		expected: true,
	},
	{
		name:     "#2",
		input:    "17-02-1990",
		expected: false,
	},
	{
		name:     "#3",
		input:    "29/02/2028",
		expected: false,
	},
}

var testAlphanum = []baseStruct{
	{
		name:      "#1",
		input:     "1234po",
		expected:  true,
		wantError: false,
	},
	{
		name:      "#2",
		input:     "^$^%$",
		expected:  false,
		wantError: true,
	},
}

var testBool = []baseStruct{
	{
		name:     "#1 bool",
		input:    "true",
		expected: true,
	},
	{
		name:     "#2 bool",
		input:    "fals",
		expected: false,
	},
}

var testValidateAlphanum = []baseStruct{
	{
		name:     "#1 true",
		input:    "aBc",
		must:     false,
		expected: true,
	},
	{
		name:     "#2 false",
		input:    "aBc1##",
		must:     true,
		expected: false,
	},
	{
		name:     "#3 must",
		input:    "aBd1",
		must:     true,
		expected: true,
	},
}

var testValidateNumber = []baseStruct{
	{
		name:     "#1 number",
		input:    "122",
		expected: true,
	},
	{
		name:     "#2 bad number",
		input:    "12s2",
		expected: false,
	},
}

var testValidateAlpha = []baseStruct{
	{
		name:     "#1 alpha",
		input:    "abcd",
		expected: true,
	},
	{
		name:     "#2 bad alpha",
		input:    "as#",
		expected: false,
	},
}

var testValidateLatin = []baseStruct{
	{
		name:     "#1 latin",
		input:    "Amazing perfect",
		expected: true,
	},
	{
		name:     "#2 latin",
		input:    "Sam <> Mas",
		expected: false,
	},
	{
		name:     "#3 latin",
		input:    "As usual & kill 12",
		expected: true,
	},
}

var testValidateNonEnglishOnly = []baseStruct{
	{
		name:     "#1 english",
		input:    "Amazing perfect",
		expected: true,
	},
	{
		name:     "#1 english",
		input:    "Amazing perfect Ú",
		expected: false,
	},
}

var testValidateGender = []baseStruct{
	{
		name:     "#1 gender",
		input:    "M",
		expected: true,
	},
	{
		name:     "#2 bad gender",
		input:    "L",
		expected: false,
	},
	{
		name:     "#3 gender",
		input:    "XL",
		expected: false,
	},
}

func TestEmailValidation(t *testing.T) {
	t.Run("Run test validation email", func(t *testing.T) {
		for _, tc := range testEmailValidation {
			err := ValidateEmail(tc.input)
			if tc.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		}
	})
}

func TestAlphanumericValidation(t *testing.T) {
	t.Run("Test alphanumeric", func(t *testing.T) {
		for _, tc := range testAlphanum {
			err := ValidateNumberOnlyInputAllowEmpty(tc.input)
			if tc.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		}
	})
	t.Run("Test ValidateAlphanumeric", func(t *testing.T) {
		for _, tc := range testValidateAlphanum {
			assert.Equal(t, tc.expected, ValidateAlphanumeric(tc.input, tc.must))
		}
	})
}

func TestValidateDateGender(t *testing.T) {
	t.Run("Run test birthdate", func(t *testing.T) {
		for _, tc := range testBirthdate {
			assert.Equal(t, tc.expected, IsValidBirthDate(tc.input))
		}
	})

	t.Run("Run test validate gender", func(t *testing.T) {
		for _, tc := range testValidateGender {
			err := ValidateGenderInput(tc.input)
			if tc.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		}
	})
}

func TestValidateAlphabet(t *testing.T) {
	t.Run("Run test validate alphabet", func(t *testing.T) {
		for _, tc := range testValidateAlpha {
			err := ValidateAlphabeticalOnlyInput(tc.input)
			if tc.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		}
	})

	t.Run("Run test validate alphabet allow empty", func(t *testing.T) {
		m := append(testValidateAlpha, baseStruct{
			name:     "#3 alphaspace",
			input:    "",
			expected: true,
		})
		for _, tc := range m {
			err := ValidateAlphabeticalOnlyInputAllowEmpty(tc.input)
			if tc.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		}
	})
}

func TestBooleanNumberValidation(t *testing.T) {
	t.Run("Test ValidateBooleanInput", func(t *testing.T) {
		for _, tc := range testBool {
			assert.Equal(t, tc.expected, ValidateBooleanInput(tc.input))
		}
	})

	t.Run("Run test validate number", func(t *testing.T) {
		for _, tc := range testValidateNumber {
			err := ValidateNumberOnlyInput(tc.input)
			if tc.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		}
	})
}

func TestValidateLatinChar(t *testing.T) {
	t.Run("Run test validate latin only except tag", func(t *testing.T) {
		for _, tc := range testValidateLatin {
			assert.Equal(t, tc.expected, ValidateLatinOnlyExcepTag(tc.input))
		}
	})

	t.Run("Run test validate latin except tag and curly", func(t *testing.T) {
		m := append(testValidateLatin, baseStruct{
			name:     "#4",
			input:    "Pop {}",
			expected: false,
		})
		for _, tc := range m {
			assert.Equal(t, tc.expected, ValidateLatinOnlyExcepTagCurly(tc.input))
		}
	})

	t.Run("Test validate english character", func(t *testing.T) {
		for _, tc := range testValidateNonEnglishOnly {
			err := ValidateNonEnglishCharacter(tc.input)
			if tc.expected {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		}
	})
}
